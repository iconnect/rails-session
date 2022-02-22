{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Either (isRight)
import           Data.Monoid ((<>))
import           Data.Ruby.Marshal hiding (decodeEither)
import           Data.Vector (fromList)
import           System.IO.Unsafe (unsafePerformIO)
import           Test.Tasty (defaultMain, testGroup)
import           Test.Tasty.Hspec (testSpec)
import           Test.Hspec (describe, it, shouldBe, shouldSatisfy, Spec)
import           Web.Rails.Session
import qualified Web.Rails3.Session as R3
import qualified Data.List.NonEmpty as NE

-- SPECS

main :: IO ()
main = do
  rails4 <- testSpec "Web.Rails.Session: Rails4" $ specsFor Rails4
  rails3 <- testSpec "Web.Rails3.Session: Rails4" specsForRails3
  defaultMain (testGroup "All the Specs" [rails4, rails3])

specsForRails3 :: Spec
specsForRails3 = do
  let cookie = R3.Cookie $ unsafePerformIO $ BS.readFile "test/Rails3"
      secret_ = R3.Secret "test secret token for testing cookies"
      sessionIdVal_ = "3e0d672d2d594d02c8f015388ae380a8"
      csrfTokenVal_ = "fKui2MZV3u5jhGBIgvvrOi7lo0mD/Jge3e0LOAS19Vg="
      userIdVal_ = 107 :: Int
      wardenContents_ = RArray (fromList [RArray (fromList [RFixnum userIdVal_]), RIVar (RString "$2a$10$hDu7wHneNw4A.6Wg61R4vO",UTF_8)])
      cookieContents_ = RHash (fromList
                          [ (RIVar (RString "session_id",UTF_8), RIVar (RString sessionIdVal_,UTF_8))
                          , (RIVar (RString "warden.user.user.key",UTF_8), wardenContents_)
                          , (RIVar (RString "_csrf_token",US_ASCII),RIVar (RString csrfTokenVal_,US_ASCII))
                          ])


  describe "all tests" $ do
    it "should be a Right(..)" $ do
      let result = R3.decodeEither secret_ cookie
      result `shouldSatisfy` isRight

    it "should be a fully-formed Ruby object" $ do
      case R3.decodeEither secret_ cookie of
        Left e -> error $ "decodeEither failed:" ++ (show e)
        Right result -> do
          result `shouldBe` cookieContents_

    it "should look up the '_csrf_token'" $ do
      case R3.decodeEither secret_ cookie of
        Left e -> error $ "decodeEither failed:" ++ (show e)
        Right result ->
          csrfToken result `shouldBe` Just csrfTokenVal_

    it "should look up the 'session_id'" $ do
      case R3.decodeEither secret_ cookie of
        Left e -> error $ "decodeEither failed:" ++ (show e)
        Right result ->
          sessionId result `shouldBe` Just sessionIdVal_

    it "should look up the warden user_id(s)" $ do
      case R3.decodeEither secret_ cookie of
        Left e -> error $ "decodeEither failed:" ++ (show e)
        Right result ->
          R3.lookupUserIds result `shouldBe` Just (userIdVal_ NE.:| [] :: NE.NonEmpty Int)

specsFor :: Rails -> Spec
specsFor rails = do
  let cookie = unsafeReadCookie rails

  describe "decode" $ do
    it "should be a Right(..)" $ do
      let result = decodeEither Nothing secret cookie
      result `shouldSatisfy` isRight

    it "should be a fully-formed Ruby object" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "decode failed"
        Right result -> do
          result `shouldBe` rubySession
  describe "decrypt" $ do
    it "should be a Right(..)" $ do
      let result = decrypt Nothing secret cookie
      result `shouldSatisfy` isRight

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

data Rails = Rails4 | Rails3 deriving (Show)

unsafeReadCookie :: Rails -> Cookie
unsafeReadCookie rails = unsafePerformIO $
  BS.readFile ("test/" <> (show rails)) >>= pure . mkCookie

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
