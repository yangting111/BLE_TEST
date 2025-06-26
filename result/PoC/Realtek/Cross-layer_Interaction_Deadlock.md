
# Vulnerability Report: Realtek RTL8762E BLE Stack DoS via Crafted Control Packet Sequences

## 1. Summary

A critical vulnerability was discovered in **Realtek RTL8762E BLE SDK v1.4.0** that allows an attacker to cause a Denial of Service (DoS) without authentication or pairing. By sending a crafted sequence of BLE control packets, the attacker can drive the target device into an unstable state that ultimately leads to a crash or hang, requiring manual reset to recover.

---

## 2. Affected Component

- **Vendor**: Realtek  
- **Product**: RTL8762E  
- **SDK Version**: BLE SDK v1.4.0  
- **Component**: BLE protocol stack – Control Packet Handling

---

## 3. Vulnerability Details

### 3.1 Description

An attacker can exploit this vulnerability by repeatedly sending the following BLE control packet sequence:

1. `LL_VERSION_IND`  
2. `pairing_request`  
3. Multiple `LL_LENGTH_REQ` / `LL_LENGTH_RSP` exchanges

This sequence, when repeated several times, causes the target device to become unstable and eventually crash. No pairing or authentication is required.

### 3.2 Root Cause

Improper validation and state management within the BLE control procedure handler allows unexpected or repeated sequences to transition the state machine into an invalid or resource-exhausted state.

---

## 4. Proof of Concept (PoC)
Full details and scripts are available [Cross-layer_Interaction_Deadlock.py](./Cross-layer_Interaction_Deadlock.py).
1. Connect to the RTL8762E device over BLE (no pairing needed).  
2. Send the following sequence in a loop:
   - `LL_VERSION_IND`
   - `pairing_request`
   - `LL_LENGTH_REQ` 
3. Repeat several times.
4. Observe the device becomes unresponsive or crashes.

---

## 5. Steps to Reproduce

1. Flash a Realtek RTL8762E board with BLE SDK v1.4.0.  
2. Use a BLE testing tool.  
3. Initiate a BLE connection with the target device.  
4. Repeatedly send the crafted control packet sequence.  
5. Monitor for crash or communication stall.

---

## 6. Security Impact

- **Vulnerability Type**: Denial of Service (DoS)  
- **Impact**: System crash, manual reboot required  
- **Attack Vector**: Local (within BLE range)  
- **Authentication Required**: No  
- **User Interaction Required**: No

---

## 7. Attack Vectors

Attackers within Bluetooth range (10–30 meters) can send legitimate yet crafted BLE control packets in a specific sequence to crash the device. No authentication or pairing is needed, and the attack can be repeated to maintain persistent denial of service.

---


## 8. References

- Bluetooth Core Specification v5.3 – Vol 6, Part B  
- https://www.realtek.com  
- http://rtl8762e.com

---

## 9. Suggested Fix

- Add strict state machine validation for control packet handling.  
- Implement rate limiting and protection against repeated control procedures.  
- Reject control packets that violate expected flow or resource limits.
