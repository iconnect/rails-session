{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Web.Rails.Session (
  -- * Decoding
    decode
  , decodeEither
  -- * Decrypting
  , decrypt
  -- * Utilities
  , csrfToken
  , sessionId
  , lookupString
  , lookupFixnum
  -- * Lifting weaker types into stronger types
  , Cookie
  , mkCookie
  , Salt
  , mkSalt
  , SecretKeyBase
  , mkSecretKeyBase
  , DecryptedData
  , unwrapDecryptedData
  ) where

import              Control.Applicative ((<$>))
import "cryptonite" Crypto.Cipher.AES (AES256)
import "cryptonite" Crypto.MAC.HMAC (HMAC, hmac)
import "cryptonite" Crypto.Hash.Algorithms (SHA1)
import "cryptonite" Crypto.Cipher.Types (cbcDecrypt, cipherInit, makeIV)
import "cryptonite" Crypto.Error (CryptoFailable(CryptoFailed, CryptoPassed))
import              Crypto.PBKDF.ByteString (sha1PBKDF2)
import              Data.ByteString (ByteString)
import qualified    Data.ByteString as BS
import qualified    Data.ByteString.Base64 as B64
import qualified    Data.ByteArray as BA
import qualified    Data.ByteArray.Encoding as BA
import              Data.Either (Either(..), either)
import              Data.Function.Compat ((&))
import              Data.Maybe (Maybe(..), fromMaybe)
import              Data.Monoid ((<>))
import              Data.Ruby.Marshal (RubyObject(..), RubyStringEncoding(..))
import qualified    Data.Ruby.Marshal as Ruby
import              Data.String.Conv (toS)
import qualified    Data.Vector as Vec
import              Network.HTTP.Types (urlDecode)
import              Prelude (Bool(..), Eq, Int, Ord, Show, String, ($!), (.)
                            , (==), const, error, fst, show, snd)

-- TYPES

-- | Wrapper around data after it has been decrypted.
newtype DecryptedData =
  DecryptedData ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around data before it has been decrypted.
newtype EncryptedData =
  EncryptedData ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around initialisation vector.
newtype InitVector =
  InitVector ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around raw cookie.
newtype Cookie =
  Cookie ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around salt.
newtype Salt =
  Salt ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around secret.
newtype SecretKey =
  SecretKey ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around secret key base.
newtype SecretKeyBase =
  SecretKeyBase ByteString
  deriving (Show, Ord, Eq)

-- | Wrapper around raw signature.
newtype Signature =
  Signature ByteString
  deriving (Show, Ord, Eq)

-- SMART CONSTRUCTORS

-- | Lift a cookie into a richer type.
mkCookie :: ByteString -> Cookie
mkCookie = Cookie

-- | Lift salt into a richer type.
mkSalt :: ByteString -> Salt
mkSalt = Salt

-- | Lifts secret into a richer type.
mkSecretKeyBase :: ByteString -> SecretKeyBase
mkSecretKeyBase = SecretKeyBase

-- SMART DESTRUCTORS

unwrapDecryptedData :: DecryptedData -> ByteString
unwrapDecryptedData (DecryptedData deData) =
  deData

-- EXPORTS

-- | Decode a cookie encrypted by Rails.
decode :: Maybe Salt
       -> SecretKeyBase
       -> Cookie
       -> Maybe RubyObject
decode mbSalt secretKeyBase cookie =
  either (const Nothing) Just (decodeEither mbSalt secretKeyBase cookie)

-- | Decode a cookie encrypted by Rails and retain some error information on failure.
decodeEither :: Maybe Salt
             -> SecretKeyBase
             -> Cookie
             -> Either String RubyObject
decodeEither mbSalt secretKeyBase cookie = do
  case decrypt mbSalt secretKeyBase cookie of
    Left errorMessage ->
      Left errorMessage
    Right (DecryptedData deData) ->
      Ruby.decodeEither deData

-- | Decrypts a cookie encrypted by Rails. Use this if you are using a
-- serialisation format other than Ruby's Marshal format.
decrypt :: Maybe Salt
        -> SecretKeyBase
        -> Cookie
        -> Either String DecryptedData
decrypt mbSalt secretKeyBase cookie = do
  let salt = fromMaybe defaultSalt mbSalt
      (SecretKey secret) = generateSecret salt secretKeyBase
  (EncryptedData encData, InitVector initVec) <- prepare cookie secretKeyBase

  case makeIV initVec of
    Nothing ->
      Left $! "Failed to build init. vector for: " <> show initVec
    Just initVec' -> do
      let key = BS.take 32 secret
      case (cipherInit key :: CryptoFailable AES256) of
        CryptoFailed errorMessage ->
          Left (show errorMessage)
        CryptoPassed cipher ->
          Right . DecryptedData $! cbcDecrypt cipher initVec' encData
  where
    defaultSalt :: Salt
    defaultSalt = Salt "encrypted cookie"

-- UTIL

-- | Helper function for looking up the csrf token in a cooie.
csrfToken :: RubyObject -> Maybe ByteString
csrfToken = lookupString "_csrf_token" US_ASCII

-- | Helper function for looking up the session id in a cookie.
sessionId :: RubyObject -> Maybe ByteString
sessionId = lookupString "session_id" UTF_8

-- | Lookup integer for a given key.
lookupFixnum :: ByteString -> RubyStringEncoding -> RubyObject -> Maybe Int
lookupFixnum key enc rubyObject =
  case lookup (RIVar (RString key, enc)) rubyObject of
    Just (RFixnum val) ->
      Just val
    _ ->
      Nothing

-- | Lookup string for a given key and throw away encoding information.
lookupString :: ByteString
             -> RubyStringEncoding
             -> RubyObject
             -> Maybe ByteString
lookupString key enc rubyObject =
  case lookup (RIVar (RString key, enc)) rubyObject of
    Just (RIVar (RString val, _)) ->
      Just val
    _ ->
      Nothing

-- PRIVATE

-- | Generate secret key using same cryptographic routines as Rails.
generateSecret :: Salt -> SecretKeyBase -> SecretKey
generateSecret (Salt salt) (SecretKeyBase secret) =
  SecretKey $! sha1PBKDF2 secret salt 1000 64

-- | Prepare a cookie for decryption.
prepare :: Cookie -> SecretKeyBase -> Either String (EncryptedData, InitVector)
prepare (Cookie cookie) secretKeyBase = do
  let (signedBase64, signatureBase16) = split (urlDecode True cookie)
      (SecretKey secret) = generateSecret salt secretKeyBase

  signature :: ByteString <- BA.convertFromBase BA.Base16 signatureBase16

  let digest :: HMAC SHA1
      digest = hmac secret signedBase64

  verified <- 
    if BA.constEq digest signature
      then Right (base64decode signedBase64)
      else Left ("Invalid HMAC " <> show (BA.convertToBase BA.Base16 digest :: ByteString)
          <> " " <> show signatureBase16)

  let (encryptedDataBase64, ivBase64) = split verified
  Right ( EncryptedData (base64decode encryptedDataBase64)
        , InitVector (base64decode ivBase64) )
  where
    base64decode :: ByteString -> ByteString
    base64decode = B64.decodeLenient

    separator :: ByteString
    separator = "--"

    split :: ByteString -> (ByteString, ByteString)
    split s = let (l, r) = BS.breakSubstring separator s
              in (l, BS.drop (BS.length separator) r)

    salt :: Salt
    salt = Salt "signed encrypted cookie"

-- | Lookup value for a given key.
lookup :: RubyObject -> RubyObject -> Maybe RubyObject
lookup key (RHash vec) = snd <$> Vec.find (\element -> fst element == key) vec
lookup _ _ = Nothing
