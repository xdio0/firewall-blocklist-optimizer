/**
 * @file firewall.js
 * @description Script para descargar, procesar, optimizar y unificar listas de bloqueo (IPs, redes, dominios)
 * de múltiples fuentes para su uso en sistemas de seguridad como firewalls.
 * @author [xdio0]
 * @version 3.0.0 (Estable y Refactorizada)
 */

// --- DEPENDENCIAS ---
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const ipaddr = require('ipaddr.js');
const { pipeline } = require('stream/promises'); // Usado para un manejo de streams robusto

// --- RED DE SEGURIDAD ---
// Atrapa promesas rechazadas no manejadas que pueden causar salidas silenciosas del proceso.
process.on('unhandledRejection', (reason, promise) => {
    console.error('ERROR GRAVE: Se ha detectado una promesa no manejada.');
    console.error('Razón del error:', reason);
    process.exit(1);
});

// --- CONFIGURACIÓN Y CONSTANTES ---
const APP_PATH = __dirname;
const CONFIG_PATH = path.join(APP_PATH, 'config.txt');
const DB_DOWNLOADS_PATH = path.join(APP_PATH, 'downloads');
const DB_CACHE_PATH = path.join(APP_PATH, 'downloads_cache');
const URLS_FILE_PATH = path.join(APP_PATH, 'urls.csv');
const ALLOWLIST_FILE_PATH = path.join(APP_PATH, 'allowlist.txt');
const INVALID_OUTPUT_FILENAME = 'invalid.txt';
const RESUME_OUTPUT_FILENAME = 'resume.txt';

// --- FUNCIONES AUXILIARES ---

/**
 * Convierte una dirección IPv4 a su representación numérica de 32 bits (unsigned long).
 * @param {string} ipAddress - Dirección IPv4 (ej. '192.168.1.1')
 * @returns {number} Valor numérico de la IP.
 */
const ipToLong = (ipAddress) => {
    const parts = ipAddress.split('.');
    return ((parseInt(parts[0], 10) << 24) |
            (parseInt(parts[1], 10) << 16) |
            (parseInt(parts[2], 10) << 8)  |
             parseInt(parts[3], 10)) >>> 0;
};

/**
 * Convierte un valor numérico de 32 bits a su formato de cadena IPv4.
 * @param {number} long - Valor numérico de la IP.
 * @returns {string} Dirección IPv4.
 */
const ipFromLong = (long) => {
    return [
        (long >>> 24) & 255,
        (long >>> 16) & 255,
        (long >>> 8) & 255,
        long & 255
    ].join('.');
};

/**
 * Verifica si una dirección es un formato IPv4 válido.
 * @param {string} ipAddress - Cadena a validar.
 * @returns {boolean} True si es IPv4 válido.
 */
const isV4Format = (ipAddress) => {
    return ipaddr.IPv4.isValid(ipAddress);
};

/**
 * Parsea una red CIDR IPv4 y devuelve los valores decimales (long) del inicio y fin de su rango.
 * @param {string} cidrStr - La red en formato CIDR (ej. '192.168.1.0/24')
 * @returns {{original: string, start: number, end: number} | null} Objeto con el rango o null si es inválido.
 */
const parseCidrRange = (cidrStr) => {
    try {
        const parts = cidrStr.split('/');
        const ipPart = parts[0]?.trim();
        const prefixPart = parts[1]?.trim();
        if (!ipPart || !prefixPart) return null;

        if (!ipaddr.IPv4.isValid(ipPart)) return null;
        const prefix = parseInt(prefixPart, 10);
        if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;

        const ipLong = ipToLong(ipPart);
        const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const start = (ipLong & mask) >>> 0;
        const end = (start | ~mask) >>> 0;

        return { original: cidrStr, start, end };
    } catch (e) {
        return null;
    }
};

/**
 * Lee la configuración desde config.txt.
 * @param {string} filePath - Ruta al archivo de configuración.
 * @returns {{outputWebDir: string, maxLinesPerFile: number}} Objeto con la configuración.
 */
const leerConfiguracion = (filePath) => {
    const defaultConfig = {
        outputWebDir: path.join(APP_PATH, 'firewall_rules'), // <<< El valor por defecto ahora está aquí
        maxLinesPerFile: 0
    };

    if (!fs.existsSync(filePath)) {
        console.warn(`Archivo de configuración no encontrado: ${filePath}. Usando valores por defecto.`);
        return defaultConfig;
    }

    const userConfig = {};
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    lines.forEach(line => {
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('#')) {
            const [key, value] = trimmedLine.split('=');
            if (key && value) {
                userConfig[key.trim()] = value.trim();
            }
        }
    });

    // Fusiona la configuración del usuario con la por defecto. La del usuario tiene prioridad.
    return { ...defaultConfig, ...userConfig };
};

/**
 * Prepara los directorios necesarios, limpiando ejecuciones anteriores y depurando la caché huérfana.
 * @param {string} outputDir - La ruta final de salida.
 * @param {string} tempDir - La ruta temporal de salida.
 * @param {string[]} [urlsActivas=[]] - Array de URLs activas para limpiar la caché huérfana.
 */
const prepararEntorno = (outputDir, tempDir, urlsActivas = []) => {
    console.log("Preparando entorno de ejecución...");
    if (!fs.existsSync(DB_DOWNLOADS_PATH)) fs.mkdirSync(DB_DOWNLOADS_PATH, { recursive: true });
    if (!fs.existsSync(DB_CACHE_PATH)) fs.mkdirSync(DB_CACHE_PATH, { recursive: true });
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
    fs.mkdirSync(tempDir, { recursive: true });

    fs.readdirSync(DB_DOWNLOADS_PATH).forEach(file => fs.unlinkSync(path.join(DB_DOWNLOADS_PATH, file)));

    if (urlsActivas.length > 0) {
        const nombresValidos = new Set(urlsActivas.map(url => Buffer.from(url).toString('base64')));
        fs.readdirSync(DB_CACHE_PATH).forEach(file => {
            if (!nombresValidos.has(file) && file !== '.gitkeep') {
                try {
                    fs.unlinkSync(path.join(DB_CACHE_PATH, file));
                    console.log(`Caché huérfana eliminada: ${file}`);
                } catch (err) {
                    console.warn(`No se pudo eliminar archivo de caché huérfano ${file}: ${err.message}`);
                }
            }
        });
    }

    console.log("Entorno listo.");
};

/**
 * Lee las URLs y sus metadatos (contador de fallos) desde el archivo CSV.
 * @param {string} filePath - Ruta al archivo de URLs.
 * @returns {Array<{url: string, consecutiveFails: number}>} Un array de objetos con la URL y su estado.
 */
const leerUrlsDesdeArchivo = (filePath) => {
    if (!fs.existsSync(filePath)) {
        console.error(`No se encontró el archivo de URLs: ${filePath}`);
        return [];
    }
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n').map(line => line.trim()).filter(Boolean);
    const urlObjects = lines.map(line => {
        const parts = line.split(';');
        const url = parts[0]?.trim();

        // <<< EXPRESIÓN REGULAR CORREGIDA: Es insensible a mayúsculas/minúsculas y busca el patrón correcto.
        const failsMatch = line.match(/Fallas consecutivas: (\d+)/i);
        const consecutiveFails = failsMatch ? parseInt(failsMatch[1], 10) : 0;

        return { url, consecutiveFails };
    }).filter(item => item.url);

    const uniqueUrls = new Map();
    urlObjects.forEach(item => uniqueUrls.set(item.url, item));
    return Array.from(uniqueUrls.values());
};

/**
 * Descarga un archivo de forma segura usando streams y pipeline.
 * @param {string} url - La URL a descargar.
 * @param {string} filePath - La ruta donde guardar el archivo.
 * @returns {Promise<{success: boolean, fechaModificacion: string | null, error: string | null}>} El resultado de la descarga.
 */
const descargarArchivo = async (url, filePath) => {
    let response;
    try {
        response = await axios.get(url, {
            responseType: 'stream',
            timeout: 20000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; Firewall-Blocklist-Optimizer/3.0.0; +https://github.com/xdio0/firewall-blocklist-optimizer)'
            }
        });
        const writer = fs.createWriteStream(filePath);
        await pipeline(response.data, writer);
        return { success: true, fechaModificacion: response.headers['last-modified'] || 'No disponible', error: null };
    } catch (error) {
        return { success: false, fechaModificacion: null, error: error.message };
    }
};

/**
 * Lee un archivo de lista blanca y devuelve un Set con sus entradas.
 * @param {string} filePath - Ruta al archivo de la lista blanca.
 * @returns {Set<string>} Un Set con las entradas a ignorar.
 */
const leerAllowlist = (filePath) => {
    if (!fs.existsSync(filePath)) {
        return new Set();
    }
    console.log("Aplicando lista blanca (allowlist)...");
    const content = fs.readFileSync(filePath, 'utf-8');
    return new Set(content.split('\n').map(line => line.trim().split('#')[0].trim()).filter(Boolean));
};

/**
 * Escribe los archivos de salida en el directorio temporal y devuelve una promesa que se resuelve al finalizar.
 * @param {string[]} data - Array de datos.
 * @param {string} filePrefix - Prefijo del archivo.
 * @param {number} maxLinesPerFile - Límite de líneas.
 * @param {string} tempDir - El directorio temporal donde escribir.
 * @returns {Promise<void>}
 */
const escribirArchivosDeSalida = (data, filePrefix, maxLinesPerFile, tempDir) => {
    return new Promise((resolve, reject) => {
        if (data.length === 0) return resolve();

        let fileIndex = 1;
        let lineCounter = 0;
        let streamsFinished = 0;
        let totalStreams = 1;
        let stream = fs.createWriteStream(path.join(tempDir, `${filePrefix}${String(fileIndex).padStart(2, '0')}.txt`));

        const onFinish = () => { streamsFinished++; if (streamsFinished === totalStreams) resolve(); };

        stream.on('error', reject).on('finish', onFinish);
        for (let i = 0; i < data.length; i++) {
            const isLastItem = i === data.length - 1;
            stream.write(data[i] + '\n');
            lineCounter++;
            if (maxLinesPerFile > 0 && lineCounter >= maxLinesPerFile && !isLastItem) {
                totalStreams++;
                const oldStream = stream;
                stream = fs.createWriteStream(path.join(tempDir, `${filePrefix}${String(++fileIndex).padStart(2, '0')}.txt`));
                stream.on('error', reject).on('finish', onFinish);
                lineCounter = 0;
                oldStream.end();
            }
        }
        stream.end();
    });
};

/**
 * Realiza la operación atómica moviendo archivos individualmente.
 * Esto asegura que los archivos de salida se actualicen correctamente sin dejar archivos temporales.
 * @param {string} outputDir - La ruta final de salida.
 * @param {string} tempDir - La ruta temporal de salida.
 */
const finalizarProcesoAtomico = (outputDir, tempDir) => {
    console.log("Finalizando operación de escritura (moviendo archivos)...");
    for (const file of fs.readdirSync(outputDir)) {
        fs.unlinkSync(path.join(outputDir, file));
    }
    for (const file of fs.readdirSync(tempDir)) {
        fs.renameSync(path.join(tempDir, file), path.join(outputDir, file));
    }
    fs.rmdirSync(tempDir);
    console.log("Archivos de salida actualizados correctamente.");
};


// --- FUNCIONES DE PROCESAMIENTO ---

/**
 * Procesa el contenido de un archivo, clasificando cada línea.
 * @param {string} contenido - El contenido del archivo a procesar.
 * @returns {object} Un objeto con los datos clasificados y estadísticas.
 */
const procesarContenidoArchivo = (contenido) => {
    const resultados = {
        ipsIPv4: [], redesIPv4: [], ipsIPv6: [], redesIPv6: [], dominios: [], invalidas: [], lineasComentadas: [],
        stats: { validas: 0, errores: 0, redesIPv4: 0, ipsIPv4: 0, redesIPv6: 0, ipsIPv6: 0, dominios: 0 }
    };

    const lineas = contenido.split('\n');

    for (const rawLine of lineas) {
        const line = rawLine.trim();
        if (!line) continue;
        if (line.startsWith('#') || line.startsWith(';')) {
            resultados.lineasComentadas.push(line);
            continue;
        }

        const cleanLine = line.split(/[#;,|]/)[0].trim();
        if (!cleanLine) continue;

        const aclRegex = /^access-list\s+\S+\s+deny\s+ip\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+any$/;
        const aclMatch = cleanLine.match(aclRegex);

        if (aclMatch) {
            const [, ipAddr, mask] = aclMatch;
            try {
                const maskBits = ipaddr.IPv4.parse(mask).toByteArray().reduce((acc, octet) => acc + (octet.toString(2).match(/1/g) || []).length, 0);
                resultados.redesIPv4.push(`${ipAddr}/${maskBits}`);
                resultados.stats.redesIPv4++;
                resultados.stats.validas++;
            } catch (e) {
                resultados.invalidas.push(cleanLine);
                resultados.stats.errores++;
            }
        } else if (ipaddr.isValid(cleanLine.split('/')[0])) {
            try {
                const parsed = ipaddr.parse(cleanLine.split('/')[0]);
                const kind = parsed.kind();
                if (kind === 'ipv4') {
                    if (cleanLine.includes('/')) {
                        resultados.redesIPv4.push(cleanLine);
                        resultados.stats.redesIPv4++;
                    } else {
                        resultados.ipsIPv4.push(cleanLine);
                        resultados.stats.ipsIPv4++;
                    }
                    resultados.stats.validas++;
                } else if (kind === 'ipv6') {
                    if (cleanLine.includes('/')) {
                        resultados.redesIPv6.push(cleanLine);
                        resultados.stats.redesIPv6++;
                    } else {
                        resultados.ipsIPv6.push(cleanLine);
                        resultados.stats.ipsIPv6++;
                    }
                    resultados.stats.validas++;
                } else {
                    resultados.invalidas.push(cleanLine);
                    resultados.stats.errores++;
                }
            } catch (e) {
                resultados.invalidas.push(cleanLine);
                resultados.stats.errores++;
            }
        } else if (/^(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]{2,})$/.test(cleanLine)) {
            resultados.dominios.push(cleanLine);
            resultados.stats.dominios++;
            resultados.stats.validas++;
        } else {
            resultados.invalidas.push(cleanLine);
            resultados.stats.errores++;
        }
    }
    return resultados;
};

/**
 * Convierte un rango de IPs (inicio-fin) a una lista de prefijos CIDR.
 * @param {string} startIp - La IP de inicio del rango.
 * @param {string} endIp - La IP de fin del rango.
 * @returns {string[]} Un array de notaciones CIDR que cubren el rango.
 */
function rangoToCIDR(startIp, endIp) {
    let start = ipToLong(startIp);
    let end = ipToLong(endIp);
    const result = [];

    while (end >= start) {
        let maxSize = 32;
        while (maxSize > 0) {
            const mask = 0xFFFFFFFF << (32 - maxSize);
            if ((start & mask) === start) {
                break;
            }
            maxSize--;
        }

        let maxEnd = start + Math.pow(2, (32 - maxSize)) - 1;
        if (maxEnd > end) {
            maxSize++;
        }

        if (maxSize > 32) { // Evita prefijos inválidos
            result.push(ipFromLong(start) + '/32');
            start++;
            continue;
        }

        result.push(ipFromLong(start) + '/' + maxSize);
        start += Math.pow(2, (32 - maxSize));
    }
    return result;
}

/**
 * Agrupa IPs consecutivas en las redes CIDR más eficientes.
 * @param {string[]} sortedIps - Un array de IPs IPv4, pre-ordenadas numéricamente.
 * @returns {{redesAgrupadas: string[], ipsSueltas: string[]}}
 */
const agruparIpsEnRedes = (sortedIps) => {
    if (sortedIps.length === 0) {
        return { redesAgrupadas: [], ipsSueltas: [] };
    }
    const redesAgrupadas = [];
    const ipsSueltas = [];
    let rangoInicio = sortedIps[0];

    for (let i = 1; i < sortedIps.length; i++) {
        const ipAnterior = sortedIps[i - 1];
        const ipActual = sortedIps[i];
        if (ipToLong(ipActual) !== ipToLong(ipAnterior) + 1) {
            if (rangoInicio === ipAnterior) {
                ipsSueltas.push(rangoInicio);
            } else {
                redesAgrupadas.push(...rangoToCIDR(rangoInicio, ipAnterior));
            }
            rangoInicio = ipActual;
        }
    }

    // Procesar el último rango de la lista
    if (rangoInicio === sortedIps[sortedIps.length - 1]) {
        ipsSueltas.push(rangoInicio);
    } else {
        redesAgrupadas.push(...rangoToCIDR(rangoInicio, sortedIps[sortedIps.length - 1]));
    }
    return { redesAgrupadas, ipsSueltas: [...new Set(ipsSueltas)] };
};

/**
 * Optimiza las listas eliminando redes redundantes y IPs contenidas.
 * @param {string[]} ips - Array de IPs individuales.
 * @param {string[]} redes - Array de redes CIDR.
 * @returns {Promise<{ipsOptimizadas: string[], redesOptimizadas: string[]}>}
 */
const optimizarListas = async (ips, redes) => {
    console.log("Optimizando listas... (Algoritmo eficiente)");

    // --- Parte 1: Optimizar Redes (sigue siendo rápido) ---
    const cidrObjects = redes.map(r => parseCidrRange(r)).filter(Boolean);

    cidrObjects.sort((a, b) => {
        if (a.start < b.start) return -1;
        if (a.start > b.start) return 1;
        if (a.end > b.end) return -1;
        if (a.end < b.end) return 1;
        return 0;
    });

    const redesOptimizadasObj = [];
    let lastNetwork = null;
    for (const net of cidrObjects) {
        if (!lastNetwork || net.end > lastNetwork.end) {
            redesOptimizadasObj.push(net);
            lastNetwork = net;
        }
    }
    const redesOptimizadas = redesOptimizadasObj.map(net => net.original);

    // --- Parte 2: Filtrar IPs (usando búsqueda binaria) ---
    console.log("Filtrando IPs contenidas en redes optimizadas... (Búsqueda Binaria)");
    
    // El array de redes ya está ordenado por 'start', perfecto para la búsqueda.
    const redesRangos = redesOptimizadasObj;

    const ipsOptimizadas = ips.filter(singleIp => {
        const ipLong = ipToLong(singleIp);
        let left = 0;
        let right = redesRangos.length - 1;

        // Búsqueda binaria para ver si la IP está en algún rango de red.
        while (left <= right) {
            const mid = Math.floor((left + right) / 2);
            const rango = redesRangos[mid];

            if (ipLong >= rango.start && ipLong <= rango.end) {
                return false; // IP encontrada en una red, la filtramos (no la incluimos).
            }

            if (ipLong < rango.start) {
                right = mid - 1;
            } else {
                left = mid + 1;
            }
        }

        return true; // La IP no se encontró en ninguna red, la mantenemos.
    });

    console.log("Optimización completada.");
    return { ipsOptimizadas, redesOptimizadas };
};

// --- FUNCIÓN PRINCIPAL (MAIN) ---
(async () => {
    console.time("Tiempo total de procesamiento");

    const config = leerConfiguracion(CONFIG_PATH);
    const maxLinesPerFile = parseInt(config.maxLinesPerFile) || 0;
    const finalOutputWebDir = config.outputWebDir;
    const finalTempOutputWebDir = path.join(path.dirname(finalOutputWebDir), `${path.basename(finalOutputWebDir)}_temp`);

    // Imprimir la ruta de salida que se usará para confirmación.
    console.log(`Ruta de salida configurada: ${finalOutputWebDir}`);

    try {
        const urlData = leerUrlsDesdeArchivo(URLS_FILE_PATH);
        if (urlData.length === 0) {
            console.log("No hay URLs para procesar. Saliendo.");
            return;
        }

        const activeUrls = urlData.map(item => item.url);
        prepararEntorno(finalOutputWebDir, finalTempOutputWebDir, activeUrls);

        console.log(`Iniciando descarga y procesamiento de ${urlData.length} URLs en paralelo...`);
        const resultadosDescargas = await Promise.all(urlData.map(async ({ url, consecutiveFails }) => {
            const filename = Buffer.from(url).toString('base64');
            const downloadPath = path.join(DB_DOWNLOADS_PATH, filename);
            const cachePath = path.join(DB_CACHE_PATH, filename);
            let resultMessage = '';

            try {
                let downloadResult = await descargarArchivo(url, downloadPath);

                if (downloadResult.success) {
                    // Descarga exitosa: resetear contador y actualizar caché
                    fs.copyFileSync(downloadPath, cachePath);
                    resultMessage = 'Éxito';
                    consecutiveFails = 0;
                } else {
                    // Descarga fallida: incrementar contador e intentar usar caché
                    console.error(`Fallo al descargar ${url}: ${downloadResult.error}`);
                    consecutiveFails++;
                    if (fs.existsSync(cachePath)) {
                        fs.copyFileSync(cachePath, downloadPath);
                        resultMessage = `Fallo, usando versión en caché. (Fallas consecutivas: ${consecutiveFails})`;
                        downloadResult.success = true; // Forzamos el éxito para que se procese
                        downloadResult.fechaModificacion = fs.statSync(cachePath).mtime.toUTCString();
                    } else {
                        resultMessage = `Fallo, sin versión en caché disponible. (Fallas consecutivas: ${consecutiveFails})`;
                    }
                }

                if (!downloadResult.success) {
                    return { url, success: false, error: downloadResult.error, statusMessage: resultMessage, consecutiveFails };
                }

                const contenido = fs.readFileSync(downloadPath, 'utf-8');
                const resultadosProceso = procesarContenidoArchivo(contenido);
                return { url, success: true, lineCount: contenido.split('\n').length, fechaModificacion: downloadResult.fechaModificacion, resultadosProceso, statusMessage: resultMessage, consecutiveFails };

            } catch (error) {
                console.error(`Error crítico procesando la URL ${url}: ${error.message}`);
                return { url, success: false, error: error.message, statusMessage: 'Error Crítico', consecutiveFails: consecutiveFails + 1 };
            }
        }));

        // --- FASE 2: AGREGACIÓN DE DATOS ---
        console.log("\nFASE 2: Agregación de datos...");
        let todosLosResultados = { ipsIPv4: [], redesIPv4: [], ipsIPv6: [], redesIPv6: [], dominios: [], invalidas: [] };
        let lineasProcesadasUnicas = new Set();
        for (const res of resultadosDescargas.filter(r => r.success)) {
            for (const key in todosLosResultados) {
                if (res.resultadosProceso[key]) {
                    res.resultadosProceso[key].forEach(item => { if (item && !lineasProcesadasUnicas.has(item)) { todosLosResultados[key].push(item); lineasProcesadasUnicas.add(item); } });
                }
            }
        }

        // --- FASE 3: APLICACIÓN DE LISTA BLANCA ---
        console.log("FASE 3: Aplicación de lista blanca...");
        const allowlist = leerAllowlist(ALLOWLIST_FILE_PATH);
        if (allowlist.size > 0) {
            for (const key in todosLosResultados) {
                if (key !== 'invalidas') {
                    todosLosResultados[key] = todosLosResultados[key].filter(item => !allowlist.has(item));
                }
            }
        }

        // --- FASE 4: OPTIMIZACIÓN ---
        console.log("FASE 4: Optimización...");
        const ipsValidas = todosLosResultados.ipsIPv4.filter(isV4Format);
        const ipsOrdenadas = ipsValidas.sort((a, b) => ipToLong(a) - ipToLong(b));

        console.log(`Agrupando ${ipsOrdenadas.length} IPs válidas en redes...`);
        const { redesAgrupadas, ipsSueltas } = agruparIpsEnRedes(ipsOrdenadas);
        todosLosResultados.redesIPv4.push(...redesAgrupadas);

        const { ipsOptimizadas, redesOptimizadas } = await optimizarListas(ipsSueltas, todosLosResultados.redesIPv4);
        const dominiosOrdenados = [...new Set(todosLosResultados.dominios)].sort();

        // --- FASE 5: ESCRITURA DE ARCHIVOS ---
        console.log("\nFASE 5: Escritura de archivos...");
        const redesOrdenadas = redesOptimizadas.sort((a, b) => {
            const ipA = ipToLong(a.split('/')[0]);
            const ipB = ipToLong(b.split('/')[0]);
            return ipA - ipB;
        });

        await Promise.all([
            escribirArchivosDeSalida(ipsOptimizadas, 'ips', maxLinesPerFile, finalTempOutputWebDir),
            escribirArchivosDeSalida(redesOrdenadas, 'nets', maxLinesPerFile, finalTempOutputWebDir),
            escribirArchivosDeSalida(dominiosOrdenados, 'domains', maxLinesPerFile, finalTempOutputWebDir),
        ]);

        console.log("Todos los archivos de listas principales se han escrito correctamente.");

        if (todosLosResultados.invalidas.length > 0) {
            fs.writeFileSync(path.join(finalTempOutputWebDir, INVALID_OUTPUT_FILENAME),
                [...new Set(todosLosResultados.invalidas)].join('\n'));
        }

        const resumenPromise = new Promise((resolve, reject) => {
            const resumenStream = fs.createWriteStream(path.join(finalTempOutputWebDir, RESUME_OUTPUT_FILENAME));
            resumenStream.on('error', reject).on('finish', resolve);
            resumenStream.write('Resumen del procesamiento de listas negras\n-----------------------------------------\n\n');
            resumenStream.write('Estadísticas Generales:\n');
            resumenStream.write(`- URLs procesadas: ${resultadosDescargas.length}\n`);
            resumenStream.write(`- Entradas únicas totales procesadas: ${lineasProcesadasUnicas.size}\n`);
            resumenStream.write(`- IPs IPv4 únicas iniciales: ${ipsOrdenadas.length}\n`);
            resumenStream.write(`- Redes IPv4 únicas iniciales: ${[...new Set(todosLosResultados.redesIPv4)].length}\n`);
            resumenStream.write(`- Dominios únicos iniciales: ${dominiosOrdenados.length}\n`);
            resumenStream.write(`- Entradas inválidas: ${[...new Set(todosLosResultados.invalidas)].length}\n\n`);
            resumenStream.write('Salida Final Optimizada:\n');
            resumenStream.write(`- IPs IPv4 finales: ${ipsOptimizadas.length}\n`);
            resumenStream.write(`- Redes IPv4 finales: ${redesOptimizadas.length}\n`);
            resumenStream.write(`- Dominios finales: ${dominiosOrdenados.length}\n\n\n`);
            resumenStream.write('Detalles por URL procesada:\n-----------------------------------------------------------------------------------\n');
            resultadosDescargas.forEach((result) => {
                resumenStream.write('-------------------------------------[START]---------------------------------------\n');
                const status = result.success ? 'Éxito' : 'Fallo';
                resumenStream.write(`URL: ${result.url}\n`);
                resumenStream.write(`Resultado de la descarga: ${status}\n`);
                if (result.success) {
                    resumenStream.write(`Líneas en el archivo original: ${result.lineCount}\n`);
                    resumenStream.write(`Última modificación (Last-Modified): ${result.fechaModificacion || 'No disponible'}\n\n`);
                    const stats = result.resultadosProceso.stats;
                    resumenStream.write('Estadísticas de este archivo (entradas únicas):\n');
                    resumenStream.write(`- Líneas válidas: ${stats.validas}\n`);
                    resumenStream.write(`- Líneas con errores/inválidas: ${stats.errores}\n`);
                    resumenStream.write(`- Redes IPv4: ${stats.redesIPv4}\n`);
                    resumenStream.write(`- IPs IPv4: ${stats.ipsIPv4}\n`);
                    resumenStream.write(`- Redes IPv6: ${stats.redesIPv6}\n`);
                    resumenStream.write(`- IPs IPv6: ${stats.ipsIPv6}\n`);
                    resumenStream.write(`- Dominios: ${stats.dominios}\n`);
                    const comentarios = result.resultadosProceso.lineasComentadas;
                    if (comentarios.length > 0) {
                        resumenStream.write('\nDetalles del autor (comentarios en el archivo):\n');
                        comentarios.slice(0, 20).forEach((line) => { resumenStream.write(`${line}\n`); });
                        if (comentarios.length > 20) { resumenStream.write(`... y ${comentarios.length - 20} más.\n`); }
                    }
                } else {
                    resumenStream.write(`Error: ${result.error}\n`);
                }
                resumenStream.write('--------------------------------------[END]----------------------------------------\n\n');
            });
            resumenStream.end();
        });

        await resumenPromise;

        const lineasCsvNuevas = resultadosDescargas.map(res => {
            const status = res.statusMessage;
            const fecha = res.fechaModificacion || 'No disponible';
            // Formato corregido y más limpio: url;Estado;FechaModificacion
            return `${res.url};${status};${fecha}`;
        });
        fs.writeFileSync(URLS_FILE_PATH, lineasCsvNuevas.join('\n'));

        finalizarProcesoAtomico(finalOutputWebDir, finalTempOutputWebDir);

        // --- FASE 6: REPORTE FINAL EN CONSOLA ---
        console.log("\n--- RESUMEN FINAL ---");
        console.log(`IPs válidas encontradas: ${ipsOrdenadas.length}`);
        console.log(`Redes únicas iniciales: ${[...new Set(todosLosResultados.redesIPv4)].length}`);
        console.log(`Dominios únicos iniciales: ${dominiosOrdenados.length}`);
        console.log("--- SALIDA OPTIMIZADA ---");
        console.log(`Total de IPs finales: ${ipsOptimizadas.length}`);
        console.log(`Total de Redes finales: ${redesOptimizadas.length}`);
        console.log(`Total de Dominios finales: ${dominiosOrdenados.length}`);
        console.log(`Entradas inválidas encontradas: ${[...new Set(todosLosResultados.invalidas)].length}`);

    } catch (error) {
        console.error("\n\n--- !! ERROR CRÍTICO DURANTE LA EJECUCIÓN !! ---");
        console.error(error);
        console.error("El proceso ha sido abortado. Los archivos de salida no han sido modificados.");
    } finally {
        console.timeEnd("Tiempo total de procesamiento");
    }
})();