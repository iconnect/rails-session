{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}

module Web.Rails3.Session
  (
    -- * Tutorial
    -- $tutorial

    -- * Decoding
    decodeEither
  , decode
    -- * Utilities
  , lookupUserIds
    -- * Throw-away data-types
    -- $datatypes
  , Secret(..)
  , Cookie(..)
  )
where

import           Crypto.Hash                  as Hash
import           Crypto.MAC.HMAC              as HMAC
import           Data.ByteString
import           Data.ByteString              as BS
import qualified Data.ByteString.Base16       as B16
import qualified Data.ByteString.Base64       as B64
import qualified Data.Map.Strict              as Map
import           Data.Ruby.Marshal            as Marshal hiding (decode, decodeEither)
import qualified Data.Ruby.Marshal            as Marshal (decodeEither)
import           Data.Ruby.Marshal.RubyObject
import Network.HTTP.Types (urlDecode)
import Data.List.NonEmpty as NE
import Data.List as DL
import Prelude (Either(..), (>>=), (.), (==), ($), Maybe(..), return, Num(..), Int, fromIntegral, Bool(..), fst, String, either, id, const)

-- $tutorial
--
-- The easiest way to use this module is by simply calling the
-- 'extractAndDecodeEither' function. The __correct__ way is given below:
--
-- @
-- case (extractEither (CookieName "_yourapp_session") waiRequest) of
--
-- -- no active Rails session
-- Left _ -> ...
--
-- Right c -> case (decodeEither (Secret "yourSessionSecret") (Cookie c)) of
--
--   -- something went wrong in decoding the cookie. You should log "e" for debugging!
--   Left e -> ...
--
--   Right obj -> case (lookupUserIds obj) of
--
--      -- we have a Rails session-cookie, but the user has not signed-in
--     Nothing -> ...
--
--     -- signed-in user. This /may/ contain muliple userIds depending up on how you have configured Devise\/Warden in your Rails app.
--     Just userIds -> ...
-- @

-- $datatypes
--
-- These data-types exist only as a way to semantically differentiate between
-- various ByteString arguments when they are passed to functions. This is required
-- only because Haskell doesn't have proper keywords-arguments.

newtype Secret = Secret ByteString
newtype Cookie = Cookie ByteString

maybeToEither :: a -> Maybe b -> Either a b
maybeToEither _ (Just b) = Right b
maybeToEither a Nothing = Left a

-- | Decode a cookie encoded by Rails3. Please read the documentation of
-- 'decodeEither' for more details, and consider using 'decodeEither' instead of
-- 'decode'
decode :: Secret -> Cookie -> Maybe RubyObject
decode s c = either (const Nothing) Just $ decodeEither s c

-- | Decode a cookie encoded by Rails3. You can find the @Secret@ in a file
-- called @config\/initializers\/secret_token.rb@ in your Rail3 app.
--
-- __Note:__ `decodeMaybe` has not been added on purpose. When cookie decoding
-- fails, you would really want to know why. Please consider logging `Left`
-- values returned by this function in your log, to save yourself some debugging
-- time later.
decodeEither :: Secret -> Cookie -> Either String RubyObject
decodeEither (Secret cookieSecret) (Cookie x) =
  extractChecksum
  >>= compareChecksum
  >>= Marshal.decodeEither
  where
    extractChecksum :: Either String (Digest SHA1)
    extractChecksum = maybeToEither
                      "[Rails3 Cookie] Illegal checksum in cookie. Wasn't able to extract a valid HMAC checksum out of it."
                      (Hash.digestFromByteString $ fst $ (B16.decode hexChecksum))

    compareChecksum :: Digest SHA1 -> Either String ByteString
    compareChecksum checksum = if (computedChecksum == checksum) then (Right $ B64.decodeLenient b64) else (Left "[Rails3 Cookie] Checksum doesn't match")

    computedChecksum :: Digest SHA1
    computedChecksum = HMAC.hmacGetDigest (HMAC.hmac cookieSecret b64 :: HMAC SHA1)

    (b64, hexChecksum) = let (a, b) = (breakSubstring delimiter $ urlDecode False x)
                         in (a, BS.drop (BS.length delimiter) b)
    delimiter = "--"


-- NOTE: Please refer to
-- http://blog.bigbinary.com/2013/03/19/cookies-on-rails.html to understand how
-- a Rails3 cookie is encoded (NOT encyrpted). Encryption of session cookies
-- only began in Rails4. Rails3 marshals a RubyObject and base64 encodes it to
-- store it as a cookie. To ensure that it cannot be tamped with, it also adds
-- an HMAC computed with the help of a secret key/value/token.

safeHead :: [a] -> Maybe a
safeHead []    = Nothing
safeHead (x:_) = Just x

lookupKey :: (Rubyable a) => (BS.ByteString, RubyStringEncoding) -> RubyObject -> Maybe a
lookupKey key robj = (fromRuby robj :: Maybe (Map.Map (BS.ByteString, RubyStringEncoding) RubyObject))
  >>= Map.lookup key
  >>= fromRuby

-- | Lookup the Warden\/Devise UserIds from a decoded cookie. __Please note,__ a
-- cookie may contain multiple UserIds, because it /seems/ that it is possible
-- to be logged-in as multiple users simultaneously, if you define [multiple
-- user
-- models](https://github.com/plataformatec/devise/wiki/How-to-Setup-Multiple-Devise-User-Models)
-- (the underlying data-structure allows it, as well).
lookupUserIds :: (Num a) => RubyObject -> Maybe (NonEmpty a)
lookupUserIds robj =
  lookupKey ("warden.user.user.key", UTF_8) robj
  >>= (\x -> fromRuby x :: Maybe [RubyObject]) -- [[int, int int], "random string"]
  >>= safeHead
  >>= (\x -> fromRuby x :: Maybe [Int]) -- [int, int, int]
  >>= (\xs -> return $ DL.map fromIntegral xs)
  >>= NE.nonEmpty
