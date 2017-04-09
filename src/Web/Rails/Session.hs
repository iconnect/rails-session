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
  , lookupString
  , lookupFixnum
  -- * Lifting weaker types into stronger types
  , Cookie
  , mkCookie
  , Salt
  , mkSalt
  , SecretKeyBase
  , mkSecretKeyBase
  ) where

import              Control.Applicative ((<$>))
import "cryptonite" Crypto.Cipher.AES (AES256)
import "cryptonite" Crypto.Cipher.Types (cbcDecrypt, cipherInit, makeIV)
import "cryptonite" Crypto.Error (CryptoFailable(CryptoFailed, CryptoPassed))
import              Crypto.PBKDF.ByteString (sha1PBKDF2)
import              Data.ByteString (ByteString)
import qualified    Data.ByteString as BS
import qualified    Data.ByteString.Base64 as B64
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

newtype DecryptedData =
  DecryptedData ByteString
  deriving (Show, Ord, Eq)

newtype EncryptedData =
  EncryptedData ByteString
  deriving (Show, Ord, Eq)

newtype InitVector =
  InitVector ByteString
  deriving (Show, Ord, Eq)

newtype Cookie =
  Cookie ByteString
  deriving (Show, Ord, Eq)

newtype Salt =
  Salt ByteString
  deriving (Show, Ord, Eq)

newtype SecretKey =
  SecretKey ByteString
  deriving (Show, Ord, Eq)

newtype SecretKeyBase =
  SecretKeyBase ByteString
  deriving (Show, Ord, Eq)

-- SMART CONSTRUCTORS

mkCookie :: ByteString -> Cookie
mkCookie = Cookie

mkSalt :: ByteString -> Salt
mkSalt = Salt

mkSecretKeyBase :: ByteString -> SecretKeyBase
mkSecretKeyBase = SecretKeyBase

-- EXPORTS

-- | Decode a cookie encrypted by Rails.
decode :: Maybe Salt -> SecretKeyBase -> Cookie -> Maybe RubyObject
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
decrypt mbSalt secretKeyBase cookie =
  let salt = fromMaybe (Salt "encrypted cookie") mbSalt
      (SecretKey secret) = generateSecret salt secretKeyBase
      key = BS.take 32 secret
      (EncryptedData encData, InitVector initVec) = prepare cookie
  in case makeIV initVec of
       Nothing ->
         Left $! "Failed to build init. vector for: " <> show initVec
       Just initVec' ->
         case (cipherInit key :: CryptoFailable AES256) of
           CryptoFailed errorMessage ->
             Left (show errorMessage)
           CryptoPassed cipher ->
             Right . DecryptedData $! cbcDecrypt cipher initVec' encData

-- | Lookup integer for a given key.
lookupFixnum :: ByteString -> RubyStringEncoding -> RubyObject -> Maybe Int
lookupFixnum k enc m =
  case lookup (RIVar (RString k, enc)) m of
    Just (RFixnum v) ->
      Just v
    _ ->
      Nothing

-- | Lookup string for a given key and throw away encoding information.
lookupString :: ByteString
             -> RubyStringEncoding
             -> RubyObject
             -> Maybe ByteString
lookupString k enc m =
  case lookup (RIVar (RString k, enc)) m of
    Just (RIVar (RString v, _)) ->
      Just v
    _ ->
      Nothing

-- UTIL

-- | Generate secret key using same cryptographic routines as Rails.
generateSecret :: Salt -> SecretKeyBase -> SecretKey
generateSecret (Salt salt) (SecretKeyBase secret) =
  SecretKey $! sha1PBKDF2 secret salt 1000 64

-- | Prepare a cookie for decryption.
prepare :: Cookie -> (EncryptedData, InitVector)
prepare (Cookie cookie) =
  urlDecode True cookie
  & (fst . split)
  & base64decode
  & split
  & (\(x, y) -> (EncryptedData (base64decode x), InitVector (base64decode y)))
  where
    base64decode :: ByteString -> ByteString
    base64decode = B64.decodeLenient

    separator :: ByteString
    separator = "--"

    split :: ByteString -> (ByteString, ByteString)
    split = BS.breakSubstring separator

-- | Lookup value for a given key.
lookup :: RubyObject -> RubyObject -> Maybe RubyObject
lookup key (RHash vec) = snd <$> Vec.find (\element -> fst element == key) vec
lookup _ _ = Nothing
