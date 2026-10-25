# Cifrado de textos

Aplicación web en español para cifrar y descifrar textos con algoritmos
simétricos, asimétricos y clásicos. Todo se procesa en el navegador: no hay
servidor, cuentas ni envío de datos.

## Arrancar

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # typecheck + build de producción en dist/
npm run preview  # sirve el build
npm run lint
```

Requiere Node 20 o superior.

## Secciones

| Sección | Métodos |
| --- | --- |
| Simétrico | AES-GCM/CBC/CTR/CFB/ECB, ChaCha20-Poly1305, XChaCha20-Poly1305, ChaCha20, Salsa20, Twofish-CBC, Blowfish-CBC, 3DES-CBC, DES-CBC y RC4 |
| Asimétrico | RSA-OAEP (2048/3072/4096, híbrido o directo), ECIES P-256 y ElGamal 2048 híbrido |
| Clásicos | César, ROT13/47, Atbash, Vigenère, Beaufort, autoclave, afín, cercas, columnar, Playfair, Hill, Bacon, Morse, XOR, Vernam, Base64/Base64URL, hexadecimal, binario, A1Z26 y URL encode |

La aplicación abre en la sección Simétrica. Las tres secciones permanecen
montadas, así que los textos, claves y resultados no se pierden al cambiar de
pestaña. El tema claro es el predeterminado; el oscuro es opcional y se guarda
en `localStorage`. Los textos y las claves viven únicamente en memoria.

## Estructura

```
src/
  App.tsx              navegación y tema
  nav.ts               secciones visibles
  index.css            estilos claro/oscuro y responsive
  components/ui.tsx    botones, campos, paneles y salidas
  sections/            Symmetric, Asymmetric y Classic
  lib/
    symmetric.ts       algoritmos simétricos y sobres CIFRA1
    asymmetric.ts      RSA, ECIES y ElGamal
    classic.ts         cifrados clásicos y codificaciones
    kdf.ts             derivación de claves
    bytes.ts           utilidades de bytes, base64, hex y descargas
scripts/
  test-crypto.ts       ida y vuelta de todos los algoritmos
```

## Formato CIFRA1

Los cifrados producen un sobre portable:

```
CIFRA1.<base64url(JSON)>
```

El JSON incluye versión, algoritmo, KDF, longitud de clave, sal, IV/nonce y
criptograma. Al descifrar se aceptan también JSON en claro o JSON en base64. La
contraseña se deriva con PBKDF2-SHA256 (210.000 iteraciones por defecto) y una
sal aleatoria; también se puede usar una clave hexadecimal directa.

## Comprobar la criptografía

```bash
npx --yes tsx scripts/test-crypto.ts
```

El script comprueba ida y vuelta con texto Unicode en todos los algoritmos
simétricos, RSA, ECIES, ElGamal y los métodos clásicos.

## Seguridad y límites

- Todo el procesamiento es local; no hay backend, cuentas ni telemetría.
- Las claves privadas no se persisten: al recargar desaparecen. Se pueden
  exportar e importar manualmente en JSON.
- DES, 3DES, RC4, AES-ECB y los cifrados clásicos se incluyen con fines
  educativos. No protegen información real.
- Es una práctica didáctica, no un gestor de secretos auditado.
