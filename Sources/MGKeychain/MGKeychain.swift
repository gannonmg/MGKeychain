//
//  KeychainManager.swift
//  MGKeychain
//
//  Created by Matt Gannon on 8/12/22.
//
//  Adapted from https://stackoverflow.com/a/37539998/11556801
//

import Foundation
import Security

public extension NSNotification.Name {
    static let keychainUpdated: NSNotification.Name = .init("keychainUpdated")
}

public enum KeychainError: Error {
    case failedToConvertToData
    case failedToDeleteValue(key: String, err: String? = nil)
    case failedToAddValue(key: String)
    case failedToLoadValue(key: String)
    case failedToGetData(key: String)
    case failedToDecodeValue(key: String)
}

public final class KeychainManager {
    
    public static let shared: KeychainManager = .init()
    private init() {}

    public func save(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.failedToConvertToData
        }
        
        try save(key: key, data: data)
        NotificationCenter.default.post(name: .keychainUpdated, object: nil)
    }
    
    public func get(for key: String) throws -> String {
        let data = try load(key: key)
        guard let value = String(data: data, encoding: .utf8) else {
            throw KeychainError.failedToDecodeValue(key: key)
        }
        
        return value
    }
    
    public func remove(key: String) throws {
        try delete(key: key)
        NotificationCenter.default.post(name: .keychainUpdated, object: key)
    }
    
    public func clearAll() {
        let secItemClasses = [
            kSecClassGenericPassword,
            kSecClassInternetPassword,
            kSecClassCertificate,
            kSecClassKey,
            kSecClassIdentity
        ]
        
        for itemClass in secItemClasses {
            let spec: NSDictionary = [kSecClass: itemClass]
            SecItemDelete(spec)
        }
    }

    private func save(key: String, data: Data) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword as String,
                                    kSecAttrAccount as String: key,
                                    kSecValueData as String: data]
        
        SecItemDelete(query as CFDictionary)
        
        let addStatus: OSStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == noErr else {
            throw KeychainError.failedToAddValue(key: key)
        }
    }
    
    private func load(key: String) throws -> Data {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: key,
                                    kSecReturnData as String: kCFBooleanTrue!,
                                    kSecMatchLimit as String: kSecMatchLimitOne]

        var dataTypeRef: AnyObject?
        let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        guard status == noErr else {
            throw KeychainError.failedToLoadValue(key: key)
        }
        
        guard let data = dataTypeRef as? Data else {
            throw KeychainError.failedToGetData(key: key)
        }

        return data
    }
    
    private func delete(key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        // Delete any existing items
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess {
            print("Successfully removed key \(key)")
        } else if let err: CFString = SecCopyErrorMessageString(status, nil) {
            let errString: String = .init(err)
            throw KeychainError.failedToDeleteValue(key: key, err: errString)
        } else {
            throw KeychainError.failedToDeleteValue(key: key, err: nil)
        }
    }
    
}

extension Data {
    init<T>(from value: T) {
        self = withUnsafePointer(to: value) { (ptr: UnsafePointer<T>) -> Data in
            return Data(buffer: UnsafeBufferPointer(start: ptr, count: 1))
        }
    }

    func to<T>(type: T.Type) -> T {
        return self.withUnsafeBytes { $0.load(as: T.self) }
    }
}
