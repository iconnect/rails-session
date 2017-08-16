{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Either (isRight, isLeft)
import           Data.Monoid ((<>))
import           Data.Ruby.Marshal hiding (decodeEither)
import           Data.Vector (fromList)
import           System.IO.Unsafe (unsafePerformIO)
import           Test.Tasty (defaultMain, testGroup)
import           Test.Tasty.Hspec (describe, context, it, shouldBe, shouldSatisfy, testSpec, Spec)
import           Web.Rails.Session

-- SPECS

main :: IO ()
main = do
  rails4 <- testSpec "Web.Rails.Session: Rails4" $ specsFor Rails4
  defaultMain (testGroup "All the Specs" [rails4])

specsFor :: Rails -> Spec
specsFor rails = do
  let cookie = unsafeReadCookie rails Valid
      invalidSignatureCookie = unsafeReadCookie rails InvalidSignature

  describe "decode" $ do
    context "valid cookie" $ do
      it "should be a Right(..)" $ do
        let result = decodeEither Nothing secret cookie
        result `shouldSatisfy` isRight

      it "should be a fully-formed Ruby object" $ do
        case decodeEither Nothing secret cookie of
          Left _ -> error "decode failed"
          Right result -> do
            result `shouldBe` rubySession

    context "invalid signature" $ do
      it "should be a Left(..)" $ do
        let result = decodeEither Nothing secret invalidSignatureCookie
        result `shouldSatisfy` isLeft

  describe "decrypt" $ do
    context "valid cookie" $ do
      it "should be a Right(..)" $ do
        let result = decrypt Nothing secret cookie
        result `shouldSatisfy` isRight

    context "invalid signature" $ do
      it "should be a Left(..)" $ do
        let result = decrypt Nothing secret invalidSignatureCookie
        result `shouldSatisfy` isLeft

  describe "csrfToken" $ do
    it "should look up the '_csrf_token'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          csrfToken result `shouldBe` Just csrfTokenVal

  describe "sessionId" $ do
    it "should look up the 'session_id'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          sessionId result `shouldBe` Just sessionIdVal

  describe "lookupString" $ do
    it "should look up the '_csrf_token'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          lookupString "_csrf_token" US_ASCII result `shouldBe`
          Just csrfTokenVal

    it "should look up the 'session_id'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          lookupString "session_id" UTF_8 result `shouldBe`
          Just sessionIdVal

    it "should look up the 'token'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          lookupString "token" US_ASCII result `shouldBe`
          Just authToken

-- EXAMPLES

example :: FilePath -> IO (Maybe ByteString)
example path = do
  rawCookie <- BS.readFile path
  let appSecret = mkSecretKeyBase "development_secret_token"
  let cookie = mkCookie rawCookie
  case decodeEither Nothing appSecret cookie of
    Left _ ->
      pure Nothing
    Right rubyObject ->
      pure $ sessionId rubyObject

-- UTIL

data Rails = Rails4 deriving (Show)

data CookieVariant = Valid | InvalidSignature deriving (Show)

unsafeReadCookie :: Rails -> CookieVariant -> Cookie
unsafeReadCookie rails cookieVariant = unsafePerformIO $
  mkCookie <$>
  BS.readFile ("test/cookies/" <> show rails <> "-" <> show cookieVariant)

-- CONFIG

secret :: SecretKeyBase
secret = mkSecretKeyBase "development_secret_token"

-- VALUES

authToken :: ByteString
authToken = "GT1EYH9X8OXYqup4HwnQIvfnh59TqNys1IvukVXpXR8="

sessionIdVal :: ByteString
sessionIdVal = "912a0abcf3d64e0d9d2bdb601b9e8224"

csrfTokenVal :: ByteString
csrfTokenVal = "c9kRzi8L7oj2MPI/QlqYpQ79WR6YfKTDob6PGl9V2pg="

rubySession :: RubyObject
rubySession =
  RHash
    (fromList
       [ ( RIVar (RString "session_id", UTF_8)
         , RIVar (RString sessionIdVal, UTF_8))
       , ( RIVar (RString "_csrf_token", US_ASCII)
         , RIVar
             (RString csrfTokenVal, US_ASCII))
       , ( RIVar (RString "token", US_ASCII)
         , RIVar (RString authToken, UTF_8))
       ])
