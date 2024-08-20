module Web.Rails.Session.Types where

import Data.ByteString (ByteString)

-- TYPES

newtype Secret = Secret ByteString

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
