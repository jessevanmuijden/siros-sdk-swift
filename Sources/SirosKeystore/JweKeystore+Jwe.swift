// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(CryptoKit)
import CryptoKit
import Foundation
import SirosCredentials

// The container's JWE layer, moved out of `JweKeystore.swift` unchanged (apart
// from losing `private`, which an extension in another file needs) to keep that
// file under the lint file-length limit. Both functions use only their parameters.
extension JweKeystore {
    // MARK: - JWE encrypt/decrypt (A256GCMKW / A256GCM)

    /// Decrypt a JWE compact serialization using A256GCMKW / A256GCM.
    func decryptJwe(_ jweString: String, mainKey: SymmetricKey) throws -> [String: Any] {
        let parts = jweString.split(separator: ".").map(String.init)
        guard parts.count == 5 else {
            throw KeystoreError.invalidContainer("JWE must have 5 parts")
        }

        let headerData = EncryptedContainer.base64UrlDecode(parts[0])
        let encryptedKeyData = EncryptedContainer.base64UrlDecode(parts[1])
        let ivData = EncryptedContainer.base64UrlDecode(parts[2])
        let ciphertextData = EncryptedContainer.base64UrlDecode(parts[3])
        let tagData = EncryptedContainer.base64UrlDecode(parts[4])

        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw KeystoreError.invalidContainer("Invalid JWE header")
        }

        // Extract the IV from the header for key unwrapping (A256GCMKW)
        guard let headerIv = header["iv"] as? String,
              let headerTag = header["tag"] as? String else {
            throw KeystoreError.invalidContainer("Missing iv/tag in JWE header for A256GCMKW")
        }

        let kwIv = EncryptedContainer.base64UrlDecode(headerIv)
        let kwTag = EncryptedContainer.base64UrlDecode(headerTag)

        // Unwrap the Content Encryption Key (CEK) using A256GCMKW
        let kwNonce = try AES.GCM.Nonce(data: kwIv)
        let kwSealedBox = try AES.GCM.SealedBox(nonce: kwNonce, ciphertext: encryptedKeyData, tag: kwTag)
        let cekData = try AES.GCM.open(kwSealedBox, using: mainKey)
        let cek = SymmetricKey(data: cekData)

        // Decrypt content with A256GCM using the CEK
        let contentNonce = try AES.GCM.Nonce(data: ivData)
        // AAD = base64url-encoded protected header
        let aadData = Data(parts[0].utf8)
        let contentSealedBox = try AES.GCM.SealedBox(
            nonce: contentNonce,
            ciphertext: ciphertextData,
            tag: tagData
        )
        let plaintext = try AES.GCM.open(contentSealedBox, using: cek, authenticating: aadData)

        guard let json = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw KeystoreError.invalidContainer("JWE payload is not valid JSON object")
        }
        return json
    }

    /// Encrypt a payload as JWE compact serialization using A256GCMKW / A256GCM.
    func encryptJwe(_ plaintext: Data, mainKey: SymmetricKey) throws -> String {
        // Generate a random CEK (256-bit)
        var cekBytes = Data(count: 32)
        // swiftlint:disable:next force_unwrapping
        cekBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let cek = SymmetricKey(data: cekBytes)

        // Wrap CEK with A256GCMKW
        let kwNonce = AES.GCM.Nonce()
        let kwSealed = try AES.GCM.seal(cekBytes, using: mainKey, nonce: kwNonce)
        let encryptedKey = kwSealed.ciphertext
        let kwIv = Data(kwNonce)
        let kwTag = kwSealed.tag

        // Build JWE header
        let headerObj: [String: Any] = [
            "alg": "A256GCMKW",
            "enc": "A256GCM",
            "iv": EncryptedContainer.base64UrlEncode(kwIv),
            "tag": EncryptedContainer.base64UrlEncode(kwTag),
        ]
        let headerData = try JSONSerialization.data(withJSONObject: headerObj)
        let headerB64 = EncryptedContainer.base64UrlEncode(headerData)

        // Encrypt content with A256GCM
        let contentNonce = AES.GCM.Nonce()
        let aad = Data(headerB64.utf8)
        let sealed = try AES.GCM.seal(plaintext, using: cek, nonce: contentNonce, authenticating: aad)

        let parts = [
            headerB64,
            EncryptedContainer.base64UrlEncode(encryptedKey),
            EncryptedContainer.base64UrlEncode(Data(contentNonce)),
            EncryptedContainer.base64UrlEncode(sealed.ciphertext),
            EncryptedContainer.base64UrlEncode(sealed.tag),
        ]
        return parts.joined(separator: ".")
    }
}
#endif
