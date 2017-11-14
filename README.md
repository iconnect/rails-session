# rails-session

[![Build Status](https://travis-ci.org/iconnect/rails-session.svg?branch=issue-3)](https://travis-ci.org/iconnect/rails-session)

Haskell library to decrypt Ruby on Rails sessions in order to allow you to share
them between Ruby on Rails and Haskell web applications.

## Usage

``` haskell
-- | Read session id from encrypted Rails cookie on the filesystem.
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
```

See more in [Spec.hs](https://github.com/iconnect/rails-session/blob/master/test/Spec.hs).

## Contributing

1. Fork it.
2. Create your feature branch (`git checkout -b my-new-feature`).
3. Commit your changes (`git commit -am 'Add some feature'`).
4. Push to the branch (`git push origin my-new-feature`).
5. Create new Pull Request.

### Contributors

- [@filib](https://github.com/filib)
- [@adinapoli](https://github.com/adinapoli)

## Similar Libraries

- [adjust/gorails](https://github.com/adjust/gorails)
- [cconstantin/plug_rails_cookie_session_store](https://github.com/cconstantin/plug_rails_cookie_session_store)
- [instore/rails-cookie-parser](https://github.com/instore/rails-cookie-parser)
