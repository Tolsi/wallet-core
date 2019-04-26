// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Waves/Address.h"
#include "HexCoding.h"
#include "PrivateKey.h"

#include <gtest/gtest.h>

namespace TW {
    namespace Waves {

        TEST(WavesAddress, SecureHash) {
            const auto secureHash = hex(Address::secureHash(parse_hex("0157c7fefc0c6acc54e9e4354a81ac1f038e01745731")));

            ASSERT_EQ(secureHash, "a7978a753c6496866dc75ba3abcaaec796f2380037a1fa7c46cbf9762ee380df");
        }

        TEST(WavesAddress, FromPrivateKey) {
            const auto privateKey = PrivateKey(
                    parse_hex("9864a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"));
            const auto publicKey = privateKey.getPublicKey(PublicKeyType::ed25519);
            const auto address = Address(publicKey);

            ASSERT_EQ(address.string(), "3P558LKWSr3NC6z58ZD8eE78dozbnW3Y8oC");
        }

        TEST(WavesAddress, FromPublicKey) {
            const auto privateKey = PrivateKey(
                    parse_hex("9864a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"));
            const auto publicKey = privateKey.getPublicKey(PublicKeyType::ed25519);
            const auto address = Address(publicKey);

            ASSERT_EQ(address.string(), "3P558LKWSr3NC6z58ZD8eE78dozbnW3Y8oC");
        }

        TEST(WavesAddress, Invalid) {
            ASSERT_FALSE(Address::isValid(std::string("abc")));
            ASSERT_FALSE(Address::isValid(std::string("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")));
            ASSERT_FALSE(Address::isValid(std::string("3PLANf4MgtNN5v5k4NNnyx2m4zKJiw1tF9v")));
            ASSERT_FALSE(Address::isValid(std::string("3PLANf4MgtNN5v6k4NNnyx2m4zKJiw1tF8v")));
        }

        TEST(WavesAddress, Valid) {
            ASSERT_TRUE(Address::isValid(std::string("3PLANf4MgtNN5v6k4NNnyx2m4zKJiw1tF9v")));
            ASSERT_TRUE(Address::isValid(std::string("3PDjjLFDR5aWkKgufika7KSLnGmAe8ueDpC")));
            ASSERT_TRUE(Address::isValid(std::string("3PLjucTjqEfmgBF7fs2CER3fHQapCtknPeW")));
            ASSERT_TRUE(Address::isValid(std::string("3PB9ffP1YKQer3e7t283gPCLyjEfK8xrGp7")));
        }

        TEST(WavesAddress, InitWithString) {
            const auto address = Address("3PQupTC1yRiHneotFt79LF2pkN6GrGMwEy3");

            ASSERT_EQ(address.string(), "3PQupTC1yRiHneotFt79LF2pkN6GrGMwEy3");
        }

    }
} // namespace
