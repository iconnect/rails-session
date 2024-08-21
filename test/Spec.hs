{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# LANGUAGE QuasiQuotes #-}
{-# HLINT ignore "Use <&>" #-}

import           Data.ByteString (ByteString)
import           Data.Either (isRight)
import           Data.Functor ((<&>))
import           Data.Ruby.Marshal hiding (decodeEither)
import           Data.Vector (fromList)
import           Test.Hspec (describe, it, shouldBe, shouldSatisfy, Spec)
import           Test.Tasty (defaultMain, testGroup)
import           Test.Tasty.Hspec (testSpec)
import           Web.Rails.Session.Types
import           Data.Aeson.QQ
import qualified Data.ByteString as BS
import qualified Data.Aeson      as JSON
import qualified Data.List.NonEmpty as NE
import qualified Web.Rails3.Session as R3
import qualified Web.Rails4.Session as R4
import qualified Web.Rails7.Session as R7

-- SPECS

main :: IO ()
main = do
  r3Cookie <- readCookie Rails3
  r4Cookie <- readCookie Rails4
  r7Cookie <- readCookie Rails7

  rails4 <- testSpec "Web.Rails.Session: Rails4 (Marshal)" $ specsFor r4Cookie
  rails3 <- testSpec "Web.Rails3.Session: Rails4 (Marshal)" $ specsForRails3 r3Cookie
  rails7 <- testSpec "Web.Rails7.Session: Rails7 (JSON)" $ specsForRails7 r7Cookie
  defaultMain (testGroup "All the Specs" [rails7, rails4, rails3])

specsForRails3 :: Cookie -> Spec
specsForRails3 cookie = do
  let secret_ = Secret "test secret token for testing cookies"
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

    it "should be a fully-formed Ruby object" $ case R3.decodeEither secret_ cookie of
      Left e -> error $ "decodeEither failed:" ++ show e
      Right result -> do
        result `shouldBe` cookieContents_

    it "should look up the '_csrf_token'" $ case R3.decodeEither secret_ cookie of
      Left e -> error $ "decodeEither failed:" ++ show e
      Right result ->
        R4.csrfToken result `shouldBe` Just csrfTokenVal_

    it "should look up the 'session_id'" $ case R3.decodeEither secret_ cookie of
      Left e -> error $ "decodeEither failed:" ++ show e
      Right result ->
        R4.sessionId result `shouldBe` Just sessionIdVal_

    it "should look up the warden user_id(s)" $ case R3.decodeEither secret_ cookie of
      Left e -> error $ "decodeEither failed:" ++ show e
      Right result ->
        R3.lookupUserIds result `shouldBe` Just (userIdVal_ NE.:| [] :: NE.NonEmpty Int)

specsFor :: Cookie -> Spec
specsFor cookie = do

  describe "decode" $ do
    it "should be a Right(..)" $ do
      let result = R4.decodeEither Nothing secret cookie
      result `shouldSatisfy` isRight

    it "should be a fully-formed Ruby object" $ case R4.decodeEither Nothing secret cookie of
      Left _ -> error "decode failed"
      Right result -> do
        result `shouldBe` rubySession
  describe "decrypt" $ it "should be a Right(..)" $ do
    let result = R4.decrypt Nothing secret cookie
    result `shouldSatisfy` isRight

  describe "csrfToken" $ it "should look up the '_csrf_token'" $ do
    case R4.decodeEither Nothing secret cookie of
      Left _ -> error "lookup failed"
      Right result ->
        R4.csrfToken result `shouldBe` Just csrfTokenVal

  describe "sessionId" $ it "should look up the 'session_id'" $ do
    case R4.decodeEither Nothing secret cookie of
      Left _ -> error "lookup failed"
      Right result ->
        R4.sessionId result `shouldBe` Just sessionIdVal

  describe "lookupString" $ do
    it "should look up the '_csrf_token'" $ case R4.decodeEither Nothing secret cookie of
      Left _ -> error "lookup failed"
      Right result ->
        R4.lookupString "_csrf_token" US_ASCII result `shouldBe`
        Just csrfTokenVal

    it "should look up the 'session_id'" $ case R4.decodeEither Nothing secret cookie of
      Left _ -> error "lookup failed"
      Right result ->
        R4.lookupString "session_id" UTF_8 result `shouldBe`
        Just sessionIdVal

    it "should look up the 'token'" $ case R4.decodeEither Nothing secret cookie of
      Left _ -> error "lookup failed"
      Right result ->
        R4.lookupString "token" US_ASCII result `shouldBe`
        Just authToken

specsForRails7 :: Cookie -> Spec
specsForRails7 cookie = do
  describe "decode" $ do
    it "should be a Right(..)" $ do
      let result = R7.decodeEither Nothing secret cookie
      result `shouldSatisfy` isRight

    it "should be a fully-formed JSON (Rails) object" $ do
      case R7.decodeEither Nothing secret cookie of
        Left x -> fail (show x)
        Right result -> result `shouldBe` rubyJSONObject

-- EXAMPLES

_example :: FilePath -> IO (Maybe ByteString)
_example path = do
  rawCookie <- BS.readFile path
  let appSecret = mkSecretKeyBase "development_secret_token"
  let cookie = mkCookie rawCookie
  case R4.decodeEither Nothing appSecret cookie of
    Left _ ->
      pure Nothing
    Right rubyObject ->
      pure $ R4.sessionId rubyObject

-- UTIL

data Rails =
    Rails4
  | Rails3
  | Rails7
  deriving (Show)

readCookie :: Rails -> IO Cookie
readCookie rails = BS.readFile ("test/" <> show rails) <&> mkCookie

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

rubyJSONObject :: JSON.Value
rubyJSONObject = [aesonQQ|{"_rails":{"message":"eyJzZXNzaW9uX2lkIjoiMjY1ZWY5NmVjOTIxMmM3ZGJhOWRjZTM3OGRmNDBjYjIiLCJsb2NhbGUiOiJlbl9HQiIsImJyYW5kaW5nIjoiaXJpc19jb25uZWN0IiwiY3VycmVudF9vcmdhbml6YXRpb25faWQiOjEsIl9jc3JmX3Rva2VuIjoiMTlGMkVlSmRrdUM4TzJxM2tTX3gtVnV1cWd5cWc0N2tXVVFFYW9Nbm5UNCIsInRva2VuIjoidzNSM2Q1ekJHdFFDdkw4eEZtUDlsY0g5TkVQWFprMzhTaUtBMURpWGEwUT0iLCJjdXJyZW50X3VzZXJfaWQiOjEsIm91dHN0YW5kaW5nX2V1bGFzIjpbXX0=","exp":null,"pur":"cookie._athena_new_session"}}|]
