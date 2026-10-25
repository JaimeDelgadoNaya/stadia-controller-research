# Verified original Stadia FillMemory policy — offline-only audit

**Result (25 October 2026):** the original restricted signed RAM loader (100,672 bytes; SHA-256 `c39ea8962cc3094a9167ba80634f1ea0652b747b4572d1de2802d9f2f4e144c5`) was checked successfully in the isolated [GitHub Actions job](https://github.com/JaimeDelgadoNaya/stadia-controller-research/actions/runs/40233274137). The binary was fetched temporarily from a public archive, checksum-verified, and not committed or uploaded as an artifact. No controller or hardware was accessed.

## Confirmed route

- The FillMemory command is enabled at tag `0x05`, and its dispatcher at `0x20003380` invokes the memory-interface `fill` method via an indirect call.
- The initialized global at `0x202081F4` points to the interface at `0x20015E8C`; its `+0x0C` entry initially contains `0x20003C87`, i.e. Thumb function `0x20003C86`.
- At `0x20003C94`, that function sets policy **operation 0**, then calls the shared policy function `0x200039A8` at `0x20003C96`. It also invokes additional region/map checks at `0x20003B30` and `0x200039F4` before an indirect backend call.
- The earlier audited WriteMemory path also uses policy function `0x200039A8`, but with **operation 2**.

The operation-specific policy selects **different whitelists**.

| FillMemory operation 0: start | Inclusive end |
|---|---|
| `0x00002000` | `0x00002003` |
| `0x400F8030` | `0x400F803B` |
| `0x402A8014` | `0x402A8017` |
| `0x402A8080` | `0x402A8083` |
| `0x402A80A0` | `0x402A80BF` |

**Neither the Execute enable field `0x200159E0` nor the Call enable field `0x200159EC` belongs to these regions.** For positive **nonwrapping** lengths and normal initialized state, FillMemory does not provide a direct way to patch those command-table gates.

**Unresolved:** the policy computes a 32-bit end address using `start + length - 1`. A wrapped result demands separate analysis of downstream checks and memory-backend effects. This is not a demonstrated out-of-range write, control-flow exploit, secure-boot bypass or recoverable firmware modification.

## Reproduce without hardware

```sh
python -m tools.audit_fillmemory_verified local/restricted_ivt_flashloader.bin --out local/fillmemory-verified.json
python -m tools.audit_fillmemory_cfg local/restricted_ivt_flashloader.bin --out local/fillmemory-cfg.json
python -m unittest tests.test_fillmemory_cfg tests.test_fillmemory_verified -v
```

The additional bounded callgraph deliberately leaves indirect calls and conditional state unresolved. A discovered call is not proof of runtime execution. No USB or flash operations occur.
