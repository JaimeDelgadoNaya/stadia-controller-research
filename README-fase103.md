# Fase 103: codec Xbox compilado para Cortex-M7 y seguridad de firma

Resultado comprobado offline: objeto ELF32 ARM Thumb EABI5 (NO ejecutable), y análisis de IVT/CSF de imágenes originales públicas. [Informe en español](docs/es/ruta-real-firmware-stadia-fase103.md).

```bash
python -m unittest tests.test_arm_boot_evidence_phase103 -v
python -m tools.verify_arm_codec_phase103 --codec-dir firmware_codec --out-dir build/arm_phase103
```

Requiere Clang con soporte `armv7em-none-eabi`. No genera firmware instalable. El objeto ARM disponible como descarga **no** es una imagen de arranque ni debe grabarse en ninguna flash. El script `audit_signed_regions_phase103` es un parser de datos, no una herramienta para flashear.
