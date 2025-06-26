
# 1. Vulnerability Report: BLE State Machine Flaw in Cypress PSoC4 Allows Authentication Bypass

## 1. Summary

A vulnerability was discovered in the Bluetooth Low Energy (BLE) stack of **Cypress PSoC4 BLE SDK v3.66**, which allows an attacker to bypass the authentication process via a malformed state transition. By injecting a crafted `pairing_failed` packet immediately after initiating a pairing request, the attacker can force the device into an inconsistent state, allowing the transmission of encryption setup messages (`LL_ENC_REQ`) without completing proper authentication.

---

## 2. Affected Component

- **Vendor**: Cypress (Infineon)
- **Product**: Cypress PSoC4
- **SDK Version**: BLE SDK v3.66
- **Component**: BLE protocol stack – Pairing and Link Layer state machine

---

## 3. Vulnerability Details

### 3.1 Description

The Bluetooth Core Specification requires that devices reject encryption-related procedures if the pairing process fails or is not completed. However, in this flawed implementation, if a `pairing_failed` packet is sent immediately after a pairing request, the device does not properly revert to a safe state. This allows an attacker to proceed with sending `LL_ENC_REQ` messages, effectively entering the encryption phase without authentication or key exchange.

### 3.2 Root Cause

The BLE stack incorrectly allows a state transition from "Pairing Failed" to "Encryption Initiation," violating protocol logic. This results in a security state mismatch and enables attackers to initiate encrypted communication without proper credentials.

---

## 4. Proof of Concept (PoC)
Full details and scripts are available [Auth_bypass.py](./Auth_bypass.py).
1. Establish BLE connection with target Cypress PSoC4 device.
2. Send a valid `pairing_request` packet.
3. Immediately send a crafted `pairing_failed` packet.
4. Follow up with an `LL_ENC_REQ` packet.
5. Target device transitions into encryption phase without enforcing authentication.

---

## 5. Steps to Reproduce

1. Use a BLE fuzzer to connect to the Cypress PSoC4 device running BLE SDK v3.66.
2. Begin a fake pairing procedure and inject a `pairing_failed` packet early in the process.
<img src="picture/1.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">

3. Monitor device behavior upon receiving a subsequent `LL_ENC_REQ`.
<img src="picture/2.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">
4. Observe that the device enters the encryption phase without completing the required pairing.
<img src="picture/3.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">

---

## 6.  Security Impact

- **Vulnerability Type**: Insecure Permissions / State Machine Violation
- **Impact**: Authentication Bypass, Unauthorized Encryption, Privilege Escalation
- **Attack Vector**: Local (within BLE range)
- **Authentication Required**: No
- **User Interaction Required**: No

---

## 7. Attack Vectors

An attacker within BLE communication range (typically 10–30 meters) can exploit this flaw during device pairing. By injecting a pairing failure and continuing the encryption handshake, they bypass authentication controls and potentially gain access to secure services.

---

## 8. References

- Bluetooth Core Specification v5.3 – Vol 3, Part H
- https://www.infineon.com/cms/en/design-support/tools/sdk/psoc-software/psoc-4-components/psoc-creator-component-datasheet-bluetooth-low-energy-ble/

---

## 9. Suggested Fix

- Introduce strict state validation checks before accepting `LL_ENC_REQ`.
- Ensure that pairing failure reverts all secure session state.
- Drop all encryption-related requests if pairing was not successfully completed.
