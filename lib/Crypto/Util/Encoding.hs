{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
This module implements some auxialiary functions related to encoding schemes.
-}

module Crypto.Util.Encoding (injectiveConcat, (<||>))
where

import Codec.Binary.Base64.String

-- |A simple, injective concatenation function. We use it to prevent encoding
-- problems. Consider the following example: we want to MAC a message, followed
-- by the name of the user who sent it. A simple scheme would be: MAC(msg ++
-- user). The problem is however that now the (msg, user) pairs ("foobar", "23")
-- and ("foo", "bar23") leave the same MAC value. This function prevents such
-- situations.
injectiveConcat :: String -- ^ The first string
                   -> String -- ^ The second string
                   -> String -- ^ The result
injectiveConcat x y = encode(x) ++ "|" ++ encode(y)

-- |A convenient name for injectiveConcat.
(<||>) :: String -> String -> String
(<||>) = injectiveConcat
