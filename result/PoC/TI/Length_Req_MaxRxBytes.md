
# Vulnerability Report: Improper Enforcement of MaxRxOctets Bounds in TI CC2652RB BLE SDK

## 1. 📌 Summary
A denial-of-service (DoS) vulnerability was identified in the **Texas Instruments CC2652RB LaunchPad** using the **SimpleLink CC13XX CC26XX SDK version 7.41.00.17**. The BLE stack fails to enforce lower bounds on `MaxRxOctets` during the LL Data Length Update procedure. According to the Bluetooth Core Specification, `MaxRxOctets` must lie within the range **27–251 bytes**. However, a malicious central can transmit an `LL_LENGTH_REQ` with an invalid `MaxRxOctets` value such as **5**. If the peripheral accepts this without proper validation, its receive buffer is effectively degraded to just 5 bytes. While the connection remains active, any incoming packets larger than 5 bytes will be silently dropped, leading to semantic inconsistency and a soft deadlock condition.

## 2. 🧩 Affected Component
- **Vendor**: Texas Instruments  
- **Product**: CC2652RB LaunchPad Development Kit  
- **SDK Version**: SimpleLink CC13XX CC26XX SDK 7.41.00.17  
- **Source Component**: BLE Link Layer - `LL_LENGTH_REQ` Handling

## 3. ⚠️ Vulnerability Details

### 3.1 Description
The BLE Link Layer supports the Data Length Update procedure via `LL_LENGTH_REQ`, where both peers exchange their maximum transmission (`MaxTxOctets`) and reception (`MaxRxOctets`) capabilities. Per the Bluetooth Core Spec, `MaxRxOctets` must be **at least 27 bytes**. If a central device sends a request with a value below this threshold (e.g., 5), and the peripheral does **not** validate it properly, the peripheral will silently accept this invalid configuration.

This forces the peripheral’s receive buffer size to drop to 5 bytes. While the connection remains “alive,” any data packet exceeding 5 bytes will be silently dropped by the peripheral, causing protocol-level miscommunication. This creates a **semantic inconsistency** and a **soft deadlock**—where the device is operational but all meaningful communication is effectively broken.

### 3.2 Root Cause
The BLE stack does not enforce the minimum bound of 27 bytes on `MaxRxOctets`, violating Bluetooth Core Specification requirements and allowing devices to be configured into an invalid and unusable state.

## 4. 🔧 Proof of Concept (PoC)
Full details and scripts are available [Length_Req_MaxRxBytes.py](./Length_Req_MaxRxBytes.py).

1. Initiate a BLE connection to the target peripheral device.
2. Send an `LL_LENGTH_REQ` with `MaxRxOctets = 0x05` and `MaxTxOctets = 0xFB`.
3. Once accepted by the peripheral, send any valid BLE packet >5 bytes.
4. The peripheral silently drops the packet. No crash occurs, but the communication is broken.

## 5. ✅ Steps to Reproduce
1. Set up a TI CC2652RB LaunchPad device running BLE stack from SDK 7.41.00.17.  
2. From a BLE central tool, establish a connection.  
3. Inject an `LL_LENGTH_REQ` PDU with an invalid `MaxRxOctets` value (e.g., 5).  
<img src="picture/4.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">
4. Observe that the device does not reject the request.  
<img src="picture/5.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">

5. Send a valid packet >5 bytes and confirm it is silently discarded.
<img src="picture/6.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">
6. Only packets with segmentation ≤ 5 were received.
<img src="picture/7.png" alt="Inject an `LL_LENGTH_REQ` PDU" width="70%">

## 6. 🔒 Security Impact
- **Vulnerability Type**: Denial of Service (DoS) / Semantic State Corruption  
- **Impact**: Communication becomes silently ineffective  
- **Attack Vector**: Local (over-the-air BLE)  
- **User Interaction Required**: No

## 7. 📐 Attack Vectors
By setting `MaxRxOctets` below the minimum allowed size (e.g., 5), the attacker creates a logically “alive” but semantically “non-functional” communication channel. Any standard BLE data above 5 bytes (e.g., GATT writes or notifications) is dropped without feedback, leading to session desynchronization and application-layer failures.


## 8. 📘 References
- Bluetooth Core Specification v5.3 – Vol 6, Part B, Section 4.2  
- TI CC13XX / CC26XX SDK Documentation  
- http://cc2652rb.com  
- http://texas.com

## 9. 🛠️ Suggested Fix
- Enforce strict validation of `MaxRxOctets` and `MaxTxOctets` against Bluetooth specification bounds (min: 27, max: 251).  
- Reject or renegotiate invalid values in `LL_LENGTH_REQ`.  
- Introduce logging and defensive mechanisms to prevent semantic inconsistencies in accepted DLE parameters.
