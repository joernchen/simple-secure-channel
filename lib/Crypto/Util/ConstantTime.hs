{-
 - ----------------------------------------------------------------------------
 - "THE BEER-WARE LICENSE" (Revision 42):
 - <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 - can do whatever you want with this stuff. If we meet some day, and you
 - think this stuff is worth it, you can buy me a beer in return Gregor Kopf
 - ----------------------------------------------------------------------------
 -}

{-|
This module aims to provide functions for evaluating expressions in constant
time. This is one possible mitigation against timing-based side-channel
attacks. Although it will likely not cause any harm, it is not entirely clear
how effective this protection scheme is. You should therefore not rely on it.
-}
module Crypto.Util.ConstantTime (constantChoice)
where
import Control.DeepSeq
-- |We use that to force the evaluation of two different branches
-- in the code. Hopefully, it will give us a constant execution
-- time of our square and multiply algorithm.
constantChoice :: (NFData a) => 
                  Bool -- ^ The choice to branch on
                  -> a -- ^ Value for choice == True
                  -> a -- ^ Value for choice == False
                  -> a -- ^ Result value
constantChoice True  x y = y `deepseq` x
constantChoice False x y = x `deepseq` y
