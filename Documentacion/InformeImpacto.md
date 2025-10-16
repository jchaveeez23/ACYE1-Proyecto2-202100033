# **Informe de Impacto Proyecto 2**

---

## **1. Introducción**
El presente informe analiza el impacto técnico y académico del desarrollo de un cifrador **AES-128 (Advanced Encryption Standard)** implementado completamente en lenguaje ensamblador para la arquitectura **ARM64**.  
El objetivo principal del proyecto es comprender en detalle el funcionamiento interno del proceso de cifrado simétrico AES, optimizar su ejecución a bajo nivel y generar trazas intermedias que faciliten la depuración y el análisis de cada ronda del algoritmo.  

Esta implementación contribuye a la formación de competencias en **seguridad informática, arquitectura de computadoras y criptografía aplicada**, demostrando el dominio de manipulación de memoria, operaciones bit a bit y optimización en bajo nivel.

---

## **2. Contexto de aplicación**
El cifrado AES-128 es ampliamente utilizado en contextos que requieren **confidencialidad y seguridad de la información**, como:
- Comunicaciones seguras (TLS, VPN, SSH).
- Almacenamiento cifrado (discos, bases de datos).
- Transmisión de datos en IoT y sistemas embebidos.

Sin embargo, la mayoría de implementaciones modernas se basan en bibliotecas de alto nivel.  
El presente proyecto busca **acercar el algoritmo al nivel del procesador**, mostrando cómo se pueden ejecutar sus etapas —SubBytes, ShiftRows, MixColumns, AddRoundKey y KeyExpansion— directamente mediante instrucciones ensamblador.

Esta aproximación tiene impacto directo en **entornos de hardware embebido**, donde los recursos son limitados y el control de cada ciclo de CPU es esencial.

---

## **3. Impacto técnico**

### **3.1. Optimización y eficiencia**
Implementar AES-128 en ensamblador permite:
- Reducir el uso de memoria (solo se reservan bytes estrictamente necesarios en `.bss`).
- Minimizar llamadas a funciones externas y evitar overhead de librerías.
- Lograr mayor velocidad de ejecución frente a implementaciones en C o Python, especialmente en plataformas **ARM64 embebidas** (como Raspberry Pi o procesadores Cortex-A).

### **3.2. Control total del flujo**
El código permite observar **cada etapa del proceso criptográfico**, imprimiendo matrices intermedias (estado, subclave, mezcla de columnas, etc.).  
Esto aporta un gran valor didáctico, ya que permite verificar los resultados en tiempo real y depurar fácilmente errores en la transformación de los datos.

### **3.3. Trazabilidad del cifrado**
La estructura modular del programa (con funciones como `subBytes`, `shiftRows`, `mixColumns`, `keyExpansion` y `runAES10`) facilita la trazabilidad de cada operación.  
Esto lo convierte en una herramienta útil para **auditorías de seguridad y validación criptográfica**, al poder comparar los resultados byte a byte con una implementación estándar.

---

## **4. Impacto académico y formativo**
El proyecto fortalece competencias en:
- **Criptografía aplicada:** comprensión del estándar AES y su estructura matemática (operaciones Galois, rotaciones, sustituciones).
- **Arquitectura ARM64:** uso de registros, direccionamiento, macros y llamadas al sistema mediante `svc`.
- **Desarrollo de software seguro:** manipulación directa de datos binarios y validación de entradas en formato hexadecimal.

Además, sirve como **recurso didáctico** para cursos de compiladores, sistemas embebidos y seguridad informática, permitiendo que los estudiantes comprendan el funcionamiento interno de un algoritmo de cifrado más allá de las abstracciones de alto nivel.

---

## **5. Impacto económico y de investigación**

### **5.1. Reducción de costos**
La ejecución directa en ensamblador elimina la necesidad de dependencias de terceros o licencias de software criptográfico, permitiendo:
- Uso en sistemas embebidos de bajo costo.
- Desarrollo de herramientas personalizadas para entornos académicos o industriales.
- Mejor aprovechamiento del hardware sin requerir equipos de alta gama.

### **5.2. Potencial en I+D**
Este tipo de implementación abre oportunidades para:
- Desarrollar versiones **optimizadas con paralelismo SIMD (NEON)**.
- Implementar **modos de operación** (CBC, CTR, GCM) en bajo nivel.
- Integrar módulos criptográficos en proyectos con **seguridad IoT o encriptación de datos industriales**.

---

## **6. Impacto en seguridad informática**
El proyecto demuestra la **importancia de comprender la criptografía desde la base**:
- Refuerza la seguridad mediante una implementación transparente y auditable.  
- Permite detectar vulnerabilidades que podrían pasar desapercibidas en librerías de alto nivel (p. ej. errores en padding, fugas de clave).  
- Fomenta la creación de soluciones **propias y soberanas en seguridad nacional**, especialmente útiles para instituciones académicas o gubernamentales.

---

## **7. Conclusiones**
La implementación completa de AES-128 en ensamblador ARM64 representa un logro técnico significativo que:
- Mejora la **eficiencia y el control total** sobre el proceso de cifrado.
- Contribuye a la **formación avanzada en criptografía y arquitectura de computadores**.
- Ofrece una base sólida para futuras extensiones, como el cifrado de bloques múltiples, la integración con hardware IoT o la comparación de rendimiento frente a compiladores optimizados.

El impacto del proyecto se refleja en la **reducción de dependencias externas**, la **mejor comprensión del funcionamiento interno de AES**, y su **potencial educativo y tecnológico** en entornos con recursos limitados o de investigación avanzada.

---

**Autor:** *Josue Daniel Chavez Portillo*  
**Proyecto:** *Proyecto 2: AES-128 ARM64*  
**Institución:** *Universidad de San Carlos De Guatemala*  
