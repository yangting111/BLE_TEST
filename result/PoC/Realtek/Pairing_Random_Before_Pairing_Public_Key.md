
# Vulnerability Report: Premature Pairing Random Injection in Realtek RTL8762E SDK v1.4.0

## 1. Summary
A denial-of-service (DoS) vulnerability was identified in the **Realtek RTL8762EKF-EVB** development platform using the **RTL8762E SDK v1.4.0**. During the Bluetooth Secure Connections pairing process, the device accepts a crafted **Pairing Random** packet **before** receiving the required **Pairing Public Key**, resulting in a state machine violation. This leads to a protocol inconsistency, which causes the pairing process to fail and denies further connection attempts. Repeated exploitation can render the device unable to establish secure BLE connections.

## 2. Affected Component
- **Vendor**: Realtek  
- **Device**: RTL8762EKF-EVB  
- **SDK Version**: RTL8762E SDK v1.4.0  
- **Component**: `BLE` Secure Connections pairing logic

## 3. Vulnerability Details

### 3.1 Description
Bluetooth Low Energy (BLE) Secure Connections pairing requires strict message ordering: the **Pairing Random** message must follow the successful exchange of **Pairing Public Keys**. However, the affected SDK fails to enforce this ordering. An attacker can inject a **Pairing Random** packet prematurely, which the device incorrectly accepts, thereby violating the expected state transition in the Secure Connections state machine.

This results in undefined or invalid internal state transitions, preventing successful pairing, and potentially causing the connection to drop or remain stuck.

### 3.2 Root Cause
The BLE stack does not validate the protocol state before processing `Pairing Random`. Specifically, it does not enforce the condition that the **public key exchange must be completed** prior to accepting a **random value**, as required by the Bluetooth Core Specification.

## 4. Proof of Concept (PoC)
An attacker connects to the RTL8762EKF-EVB device as a BLE central or peripheral, and immediately sends a crafted **Pairing Random** packet **before** the expected **Pairing Public Key**. This causes the device to enter an invalid state and aborts the pairing process. Full details and scripts are available [pairing_random_before_pairing_public_key.py](./pairing_random_before_pairing_public_key.py).

```
1. Attacker initiates BLE pairing
2. Before Pairing Public Key is exchanged, send malicious Pairing Random
3. Target accepts the packet → state mismatch → pairing aborted
```

## 5. Steps to Reproduce
1. Set up the RTL8762EKF-EVB running BLE peripheral with Secure Connections pairing enabled.  
2. Use a custom BLE central (e.g., modified Android stack or NRF BLE sniffer with injection).  
3. During the pairing procedure, inject a `Pairing Random` packet before the `Pairing Public Key` exchange.  

<img src="picture/2.png" alt="Inject a `Pairing Random` packets">

4. Random was received prior to its expected position in the protocol flow.

<img src="picture/1.png" alt="Inject a `Pairing Random` packets">

## 6. Security Impact
- **Vulnerability Type**: Denial of Service (DoS)  
- **Impact**: Blocks legitimate BLE secure connections  
- **Privileges Required**: None (over-the-air attack)  


## 7. Attack Vectors
An attacker in BLE range can inject a malformed or premature `Pairing Random` packet before the public key is exchanged. The victim device accepts this invalid sequence, triggering a state machine error and failing the pairing process. Repeating this behavior can lead to persistent connection denial.

## 8. References
- **Bluetooth Core Specification v5.3**, Vol 3, Part H, Section 2.4.5 (SMP State Machine)  
- Realtek RTL8762E SDK v1.4.0  
- BLE Secure Connections protocol flow diagrams

## 9. Suggested Fix
- Implement strict state validation in the BLE SMP layer: ensure that `Pairing Random` is **only accepted** after both sides have exchanged `Pairing Public Key`.  
- Discard any messages received **out of order** according to the SMP state machine.  
- Consider adding logging or debug output to help identify out-of-sequence messages during testing.

