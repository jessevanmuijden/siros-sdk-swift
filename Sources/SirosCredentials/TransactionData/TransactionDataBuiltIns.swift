// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The four built-in EC TS12 transaction data types and their payload JSON
/// Schemas (TS12 v1.0.1 section 4.3).
///
/// The schema texts below are the files the specification links, copied
/// verbatim from
/// `eudi-doc-standards-and-technical-specifications/docs/technical-specifications/api/`
/// (`ts12-urn-eudi-sca-<type>-1-data-model.json`) at main on 2026-10-06.
/// They are not edited here; `TransactionDataSchemaTests` pins their content.
public enum TransactionDataBuiltIns {
    public static let paymentType = "urn:eudi:sca:payment:1"
    public static let loginRiskType = "urn:eudi:sca:login_risk_transaction:1"
    public static let accountAccessType = "urn:eudi:sca:account_access:1"
    public static let emandateType = "urn:eudi:sca:emandate:1"

    public static let types: Set<String> = [paymentType, loginRiskType, accountAccessType, emandateType]

    /// Payload members of a built-in type that decide what the user approves
    /// (what is paid, to whom, what action). Whatever the attestation's
    /// (unauthenticated) metadata says, these are never displayed below level 2.
    public static func displayFloorPaths(forType type: String) -> [[String]] {
        let payee = [["payee", "name"], ["payee", "id"]]
        switch type {
        case paymentType: return [["amount"], ["currency"]] + payee
        case loginRiskType: return [["action"]]
        case emandateType:
            return [["purpose"], ["payment_payload", "amount"], ["payment_payload", "currency"],
                    ["payment_payload", "payee", "name"], ["payment_payload", "payee", "id"]]
        default: return []
        }
    }

    /// The payload schema of a built-in type, parsed once.
    public static func schema(forType type: String) -> JSONValue? {
        schemas[type]
    }

    /// Resolves the `$ref` file names the built-in schemas use between each
    /// other (the e-mandate schema references the payment schema by file name).
    static func schema(forReference ref: String) -> JSONValue? {
        fileNames[ref].flatMap { schemas[$0] }
    }

    private static let fileNames: [String: String] = [
        "ts12-urn-eudi-sca-payment-1-data-model.json": paymentType,
        "ts12-urn-eudi-sca-login_risk_transaction-1-data-model.json": loginRiskType,
        "ts12-urn-eudi-sca-account_access-1-data-model.json": accountAccessType,
        "ts12-urn-eudi-sca-emandate-1-data-model.json": emandateType,
    ]

    private static let schemas: [String: JSONValue] = {
        var result: [String: JSONValue] = [:]
        for (type, text) in sources {
            // Static, reviewed content: a parse failure is a programming error
            // and the type then simply has no built-in schema (fail closed).
            if let parsed = try? StrictJSON.parse(text) { result[type] = parsed }
        }
        return result
    }()

    static let sources: [String: String] = [
        "urn:eudi:sca:payment:1": #"""
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "payee": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string"
                },
                "id": {
                    "type": "string"
                },
                "logo": {
                    "type": "string",
                    "format": "uri"
                },
                "website": {
                    "type": "string",
                    "format": "uri"
                }
            },
            "required": [
                "name",
                "id"
            ]
        },
        "pisp": {
            "type": "object",
            "properties": {
                "legal_name": {
                    "type": "string"
                },
                "brand_name": {
                    "type": "string"
                },
                "domain_name": {
                    "type": "string"
                }
            },
            "required": [
                "legal_name",
                "brand_name",
                "domain_name"
            ]
        },
        "execution_date": {
            "type": "string",
            "format": "date-time"
        },
        "currency": {
            "type": "string",
            "pattern": "^[A-Z]{3}$"
        },
        "amount": {
            "type": "number"
        },
        "amount_estimated": {
            "type": "boolean"
        },
        "amount_earmarked": {
            "type": "boolean"
        },
        "sct_inst": {
            "type": "boolean"
        },
        "recurrence": {
            "type": "object",
            "properties": {
                "start_date": {
                    "type": "string",
                    "format": "date-time"
                },
                "end_date": {
                    "type": "string",
                    "format": "date-time"
                },
                "number": {
                    "type": "integer"
                },
                "frequency": {
                    "type": "string",
                    "enum": [
                        "INDA",
                        "DAIL",
                        "WEEK",
                        "TOWK",
                        "TWMN",
                        "MNTH",
                        "TOMN",
                        "QUTR",
                        "FOMN",
                        "SEMI",
                        "YEAR",
                        "TYEA"
                    ]
                },
                "mit_options": {
                    "type": "object",
                    "properties": {
                        "amount_variable": {
                            "type": "boolean"
                        },
                        "min_amount": {
                            "type": "number"
                        },
                        "max_amount": {
                            "type": "number"
                        },
                        "total_amount": {
                            "type": "number"
                        },
                        "initial_amount": {
                            "type": "number"
                        },
                        "initial_amount_number": {
                            "type": "integer"
                        },
                        "apr": {
                            "type": "number"
                        }
                    }
                }
            },
            "required": [
                "frequency"
            ]
        }
    },
    "required": [
        "transaction_id",
        "payee",
        "currency",
        "amount"
    ],
    "additionalProperties": false
}
"""#,
        "urn:eudi:sca:login_risk_transaction:1": #"""
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "service": {
            "type": "string",
            "maxLength": 100,
            "examples": [
                "Superbank Onlinebanking"
            ]
        },
        "action": {
            "type": "string",
            "maxLength": 140,
            "examples": [
                "Login to your online account."
            ]
        }
    },
    "additionalProperties": false,
    "required": [
        "transaction_id",
        "action"
    ]
}
"""#,
        "urn:eudi:sca:account_access:1": #"""
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "aisp": {
            "type": "object",
            "properties": {
                "legal_name": {
                    "type": "string"
                },
                "brand_name": {
                    "type": "string"
                },
                "domain_name": {
                    "type": "string"
                }
            },
            "required": [
                "legal_name",
                "brand_name",
                "domain_name"
            ]
        },
        "description": {
            "type": "string",
            "maxLength": 140,
            "examples": [
                "Grant access to the account's data."
            ]
        }
    },
    "additionalProperties": false,
    "required": [
        "transaction_id"
    ]
}
"""#,
        "urn:eudi:sca:emandate:1": #"""
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "transaction_id": {
            "type": "string",
            "maxLength": 36,
            "minLength": 1,
            "examples": [
                "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
            ]
        },
        "date_time": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "start_date": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-11-13T20:20:39+00:00"
            ]
        },
        "end_date": {
            "type": "string",
            "format": "date-time",
            "examples": [
                "2025-12-13T20:20:39+00:00"
            ]
        },
        "reference_number": {
            "type": "string",
            "maxLength": 50,
            "minLength": 1,
            "examples": [
                "A-98765"
            ]
        },
        "creditor_id": {
            "type": "string",
            "maxLength": 50,
            "minLength": 1,
            "examples": [
                "FR14ZZZ001122334455"
            ]
        },
        "purpose": {
            "type": "string",
            "maxLength": 1000,
            "examples": [
                "Pay monthly bill"
            ]
        },
        "payment_payload": {
            "$ref": "ts12-urn-eudi-sca-payment-1-data-model.json"
        }
    },
    "additionalProperties": false,
    "required": [
        "transaction_id"
    ]
}
"""#,
    ]
}
