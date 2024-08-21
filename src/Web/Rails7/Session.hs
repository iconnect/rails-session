{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}

module Web.Rails7.Session (
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
  ) where

import              Control.Applicative ((<$>))
import              Control.Monad
import              Crypto.PBKDF.ByteString (sha1PBKDF2, sha256PBKDF2)
import              Data.Aeson qualified as JSON
import              Data.Bifunctor
import              Data.ByteArray qualified as BA
import              Data.ByteString (ByteString)
import              Data.ByteString qualified as BS
import              Data.ByteString.Base64 qualified as B64
import              Data.ByteString.Char8 qualified as C8
import              Data.ByteString.Lazy qualified as BL
import              Data.Either (Either(..), either)
import              Data.Function.Compat ((&))
import              Data.Maybe (Maybe(..), fromMaybe)
import              Data.Monoid ((<>))
import              Data.Ruby.Marshal (RubyObject(..), RubyStringEncoding(..))
import              Data.String.Conv (toS)
import              Data.Vector qualified as Vec
import              Network.HTTP.Types (urlDecode)
import              Prelude (Bool(..), Eq, Int, Ord, Show, String, ($!), (.) , (==), const, error, fst, show, snd)
import              Prelude hiding (lookup)
import              Web.Rails.Session.Types
import "cryptonite" Crypto.Cipher.AES (AES256)
import "cryptonite" Crypto.Cipher.AESGCMSIV qualified as AESGCM
import "cryptonite" Crypto.Cipher.Types (cbcDecrypt, cipherInit, makeIV, aeadInit, AEADMode (..), aeadSimpleDecrypt, AuthTag(..))
import "cryptonite" Crypto.Error (CryptoFailable(CryptoFailed, CryptoPassed))

import Debug.Trace (traceShowId, traceShow)
import qualified Data.ByteString.Base16 as B16

data DecodingError
  = InvalidCookieFormat
  | InvalidAuthTagSize Int
  | InvalidIVSize Int
  | InvalidJSON String
  | InvalidBase64 String
  | InvalidCryptoStep String
  | MakeIVFailed String
  | DecryptionIsEmpty
  deriving (Show, Eq)

-- EXPORTS

-- | Decode a cookie encrypted by Rails.
decode :: Maybe Salt
       -> SecretKeyBase
       -> Cookie
       -> Maybe JSON.Value
decode mbSalt secretKeyBase cookie =
  either (const Nothing) Just (decodeEither mbSalt secretKeyBase cookie)

-- | Decode a cookie encrypted by Rails and retain some error information on failure.
decodeEither :: Maybe Salt
             -> SecretKeyBase
             -> Cookie
             -> Either DecodingError JSON.Value
decodeEither mbSalt secretKeyBase cookie = do
  case decrypt mbSalt secretKeyBase cookie of
    Left errorMessage ->
      Left errorMessage
    Right (DecryptedData deData) ->
      first InvalidJSON $ JSON.eitherDecode (BL.fromStrict deData)

-- | Decrypts a cookie encrypted by Rails. Use this if you are using a
-- serialisation format other than Ruby's Marshal format.
decrypt :: Maybe Salt
        -> SecretKeyBase
        -> Cookie
        -> Either DecodingError DecryptedData
decrypt mbSalt secretKeyBase cookie = do
  (EncryptedData encData, InitVector ivVec, autTag) <- prepare cookie
  nonce <- doCryptoStep $ AESGCM.nonce ivVec
  cipher <- doCryptoStep (cipherInit cipherKey :: CryptoFailable AES256)
  aad <- doCryptoStep (aeadInit AEAD_GCM cipher ivVec)
  case aeadSimpleDecrypt aad (mempty :: ByteString) encData autTag of
    Nothing -> Left DecryptionIsEmpty
    Just dt -> Right $ DecryptedData dt

  where

    cipherKey :: ByteString
    (SecretKey cipherKey) = generateSecret salt secretKeyBase

    salt :: Salt
    salt = fromMaybe defaultSalt mbSalt

    defaultSalt :: Salt
    defaultSalt = Salt "authenticated encrypted cookie"

doCryptoStep :: CryptoFailable a -> Either DecodingError a
doCryptoStep = \case
  CryptoFailed errorMessage ->
    Left (InvalidCryptoStep $ show errorMessage)
  CryptoPassed a -> Right a

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
  SecretKey $! sha256PBKDF2 secret salt 1000 32

-- | Prepare a cookie for decryption.
-- /NOTE/: Unlike Rails4, Rails7 cookies contains a final auth tag at the end.
prepare :: Cookie -> Either DecodingError (EncryptedData, InitVector, AuthTag)
prepare (Cookie cookie) =
  case tokenise "--" cookie of
    [encDataB64, ivVectorB64, autTagB64]
     -> do
       encData  <- base64decode encDataB64
       ivVector <- enforceIVLen     =<< base64decode ivVectorB64
       autTag   <- enforceAutTagLen =<< base64decode autTagB64
       Right (EncryptedData encData, InitVector ivVector, AuthTag $ BA.convert autTag)
    _ -> Left InvalidCookieFormat
  where
    base64decode :: ByteString -> Either DecodingError ByteString
    base64decode = Right . B64.decodeLenient . C8.filter (/= '\n')

    enforceAutTagLen :: ByteString -> Either DecodingError ByteString
    enforceAutTagLen b
      | BS.length b == 16
      = Right b
      | otherwise
      = Left $ InvalidAuthTagSize (BS.length b)

    enforceIVLen :: ByteString -> Either DecodingError ByteString
    enforceIVLen b
      | BS.length b == 12
      = Right b
      | otherwise
      = Left $ InvalidIVSize (BS.length b)


separator :: ByteString
separator = "--"

tokenise :: ByteString -> ByteString -> [ByteString]
tokenise x y = h : if BS.null t then [] else tokenise x (BS.drop (BS.length x) t)
    where (h,t) = BS.breakSubstring x y

-- | Lookup value for a given key.
lookup :: RubyObject -> RubyObject -> Maybe RubyObject
lookup key (RHash vec) = snd <$> Vec.find (\element -> fst element == key) vec
lookup _ _ = Nothing
