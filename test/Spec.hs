{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

import Data.ByteString (ByteString)
import Data.Either (isRight)
import Data.Ruby.Marshal hiding (decodeEither)
import Data.Vector (fromList)
import Test.Tasty (defaultMain, testGroup)
import Test.Tasty.Hspec (describe, it, shouldBe, shouldSatisfy, testSpec, Spec)
import Web.Rails.Session

main :: IO ()
main = do
  x <- testSpec "Web.Rails.Session" specs
  defaultMain (testGroup "All the Specs" [x])

specs :: Spec
specs = do
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

  describe "lookupString" $ do
    it "should look up the '_csrf_token'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          lookupString "_csrf_token" US_ASCII result `shouldBe`
          Just csrfToken

    it "should look up the 'session_id'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          lookupString "session_id" UTF_8 result `shouldBe`
          Just sessionId

    it "should look up the 'token'" $ do
      case decodeEither Nothing secret cookie of
        Left _ -> error "lookup failed"
        Right result ->
          lookupString "token" US_ASCII result `shouldBe`
          Just authToken

-- CONFIG

secret :: SecretKeyBase
secret = mkSecretKeyBase "development_secret_token"

-- VALUES

authToken :: ByteString
authToken = "GT1EYH9X8OXYqup4HwnQIvfnh59TqNys1IvukVXpXR8="

sessionId :: ByteString
sessionId = "912a0abcf3d64e0d9d2bdb601b9e8224"

csrfToken :: ByteString
csrfToken = "c9kRzi8L7oj2MPI/QlqYpQ79WR6YfKTDob6PGl9V2pg="

-- SESSIONS

cookie :: Cookie
cookie =
  mkCookie $
  "T3NpYnRsWGJsZ25qL0R4MFlZdE9wZVBrZXc3VnFHMHhYMFgvemlVUjlTekZKbERXbVd2Mkwra0xxTmNOYnZaWktBQWo3T25RV3VPRkR6RU9BQ3dub2FSWExlZmZ1RUxVWG9vZjRTbWphRzBFSW5nMVJOSklPTVRPRGxKN0tvdGxhZzVlZktLTmhxc0V1a1FCWHpwNVJGTjdON0JCbjZQWHM0R1M1SWIzeUkzalhVNWdVbnd2Z2E5RlBMSXcvR0tNSHVOZ0NiK1RBTzVxcCtMK3hJa1daYW13allNb1NyN3pOUTFBQ0tRcFNEdUVJelVMZE8rVXhwM3RhcHFONWRwby9kRStNNkRUVXNQTDNKcjF0ZWpGTUE9PS0tb3NGeEJiZ1dLeFFKcFV0WXgyUytnZz09--e996601dbf39ff5ffbf6e2f23f6ddf78c5179baa"

rubySession :: RubyObject
rubySession =
  RHash
    (fromList
       [ ( RIVar (RString "session_id", UTF_8)
         , RIVar (RString sessionId, UTF_8))
       , ( RIVar (RString "_csrf_token", US_ASCII)
         , RIVar
             (RString csrfToken, US_ASCII))
       , ( RIVar (RString "token", US_ASCII)
         , RIVar (RString authToken, UTF_8))
       ])
