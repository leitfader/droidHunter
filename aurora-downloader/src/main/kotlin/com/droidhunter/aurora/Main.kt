package com.droidhunter.aurora

import com.aurora.gplayapi.data.models.AuthData
import com.aurora.gplayapi.data.models.PlayFile
import com.aurora.gplayapi.data.serializers.LocaleSerializer
import com.aurora.gplayapi.data.serializers.PropertiesSerializer
import com.aurora.gplayapi.helpers.AppDetailsHelper
import com.aurora.gplayapi.helpers.AuthHelper
import com.aurora.gplayapi.helpers.PurchaseHelper
import com.aurora.gplayapi.helpers.TopChartsHelper
import com.aurora.gplayapi.helpers.contracts.TopChartsContract
import com.aurora.gplayapi.network.IHttpClient
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.Properties
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import kotlinx.serialization.encodeToString
import okhttp3.Headers.Companion.toHeaders
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType

private const val DEFAULT_DISPENSER = "https://auroraoss.com/api/auth"
private const val DEFAULT_DISPENSER_USER_AGENT = "com.aurora.store-4.8.1-73"
private const val DEFAULT_USER_AGENT =
    "Android-Finsky/21.5.17-21 [0] [PR] 326734551 (api=3,versionCode=82151710,sdk=36,device=emu64xa,hardware=ranchu,product=sdk_gphone64_x86_64,platformVersionRelease=16,model=sdk_gphone64_x86_64,buildId=BE2A.250530.026.D1,isWideScreen=0,supportedAbis=x86_64;arm64-v8a)"
private val DEFAULT_LOCALE: Locale = Locale.forLanguageTag("en-001")

@Serializable
data class DispenserAuth(
    val email: String,
    @SerialName("authToken")
    val auth: String
)

data class Config(
    val packageName: String,
    val output: File,
    val outputDir: File,
    val versionCode: Long?,
    val dispenserUrl: String,
    val dispenserUserAgent: String,
    val devicePropsPath: File?,
    val locale: Locale,
    val resultPath: File?,
    val userAgent: String,
    val timeoutSeconds: Long,
    val downloadRetries: Int,
    val listTopCharts: Boolean,
    val chartName: String,
    val chartType: String,
    val chartLimit: Int
)

fun main(args: Array<String>) = runBlocking {
    val config = parseArgs(args) ?: run {
        System.err.println(usage())
        return@runBlocking
    }

    val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        coerceInputValues = true
        explicitNulls = false
        serializersModule = SerializersModule {
            contextual(LocaleSerializer)
            contextual(PropertiesSerializer)
        }
    }

    val okHttpClient = OkHttpClient.Builder()
        .callTimeout(config.timeoutSeconds, TimeUnit.SECONDS)
        .connectTimeout(config.timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(config.timeoutSeconds, TimeUnit.SECONDS)
        .writeTimeout(config.timeoutSeconds, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    val dispenserHttpClient = AuroraHttpClient(okHttpClient, config.dispenserUserAgent)
    val playHttpClient = AuroraHttpClient(okHttpClient, config.userAgent)

    val properties = loadProperties(config.devicePropsPath)
    val authData = buildAnonymousAuth(
        json,
        dispenserHttpClient,
        config.dispenserUrl,
        properties,
        config.locale
    )

    if (config.listTopCharts) {
        val helper = TopChartsHelper(authData).using(playHttpClient)
        val chartValue = resolveChartValue(config.chartName)
        val chartType = resolveChartType(config.chartType)
        val cluster = helper.getCluster(chartType, chartValue)
        val packages = cluster.clusterAppList
            .mapNotNull { it.packageName }
            .filter { it.isNotBlank() }
            .distinct()
        val limited = if (config.chartLimit > 0) {
            packages.take(config.chartLimit)
        } else {
            packages
        }
        println(json.encodeToString(limited))
        return@runBlocking
    }

    val appDetailsHelper = AppDetailsHelper(authData).using(playHttpClient)
    val purchaseHelper = PurchaseHelper(authData).using(playHttpClient)

    val app = appDetailsHelper.getAppByPackageName(config.packageName)
    val versionCode = config.versionCode ?: app.versionCode
    val offerType = app.offerType

    var files = app.fileList.filter { it.url.isNotBlank() }
    if (files.isEmpty()) {
        try {
            files = purchaseHelper.purchase(config.packageName, versionCode, offerType)
        } catch (exc: Exception) {
            if (exc.javaClass.name == "com.aurora.gplayapi.exceptions.InternalException\$AppNotSupported") {
                val reason = runCatching {
                    exc.javaClass.getMethod("getReason").invoke(exc) as? String
                }.getOrNull()
                val suffix = if (!reason.isNullOrBlank()) " Reason: $reason" else ""
                throw RuntimeException(
                    "App not supported for this device profile/locale. Try --device-props or --locale.$suffix",
                    exc
                )
            }
            throw exc
        }
    }

    if (files.isEmpty()) {
        System.err.println("No downloadable files returned for ${config.packageName}")
        return@runBlocking
    }

    config.outputDir.mkdirs()

    files.forEach { file ->
        val target = File(config.outputDir, file.name)
        if (!target.exists()) {
            downloadFile(okHttpClient, file.url, target, config.downloadRetries)
        }
    }

    val baseFile = selectBaseFile(files)
    if (baseFile == null) {
        System.err.println("Unable to identify base APK for ${config.packageName}")
        return@runBlocking
    }

    val basePath = File(config.outputDir, baseFile.name)
    if (basePath.exists() && basePath != config.output) {
        basePath.copyTo(config.output, overwrite = true)
    }

    val result = mapOf(
        "packageName" to config.packageName,
        "versionCode" to versionCode,
        "output" to config.output.absolutePath,
        "outputDir" to config.outputDir.absolutePath,
        "files" to files.map { it.name }
    )

    config.resultPath?.writeText(json.encodeToString(MapSerializer, result))
    println("Downloaded ${config.packageName} to ${config.output.absolutePath}")
}

private object MapSerializer : kotlinx.serialization.KSerializer<Map<String, Any>> {
    override val descriptor = kotlinx.serialization.descriptors.buildClassSerialDescriptor("Map")
    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: Map<String, Any>) {
        val json = encoder as? kotlinx.serialization.json.JsonEncoder
            ?: throw IllegalStateException("Json encoder required")
        val map = value.mapValues { (_, v) ->
            when (v) {
                is Number -> kotlinx.serialization.json.JsonPrimitive(v)
                is Boolean -> kotlinx.serialization.json.JsonPrimitive(v)
                is String -> kotlinx.serialization.json.JsonPrimitive(v)
                is List<*> -> kotlinx.serialization.json.JsonArray(v.map { kotlinx.serialization.json.JsonPrimitive(it.toString()) })
                else -> kotlinx.serialization.json.JsonPrimitive(v.toString())
            }
        }
        json.encodeJsonElement(kotlinx.serialization.json.JsonObject(map))
    }

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): Map<String, Any> {
        throw kotlinx.serialization.SerializationException("MapSerializer does not support deserialization")
    }
}

private fun parseArgs(args: Array<String>): Config? {
    var packageName: String? = null
    var output: String? = null
    var outputDir: String? = null
    var versionCode: Long? = null
    var dispenserUrl = DEFAULT_DISPENSER
    var dispenserUserAgent = DEFAULT_DISPENSER_USER_AGENT
    var deviceProps: String? = null
    var locale = DEFAULT_LOCALE
    var resultPath: String? = null
    var userAgent = DEFAULT_USER_AGENT
    var timeoutSeconds = 60L
    var downloadRetries = 2
    var listTopCharts = false
    var chartName = "TOP_SELLING_FREE"
    var chartType = "APPLICATION"
    var chartLimit = 200

    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--package" -> packageName = args.getOrNull(++index)
            "--output" -> output = args.getOrNull(++index)
            "--output-dir" -> outputDir = args.getOrNull(++index)
            "--version-code" -> versionCode = args.getOrNull(++index)?.toLongOrNull()
            "--dispenser-url" -> dispenserUrl = args.getOrNull(++index) ?: dispenserUrl
            "--dispenser-user-agent" -> dispenserUserAgent = args.getOrNull(++index) ?: dispenserUserAgent
            "--user-agent" -> userAgent = args.getOrNull(++index) ?: userAgent
            "--device-props" -> deviceProps = args.getOrNull(++index)
            "--locale" -> {
                val localeArg = args.getOrNull(++index)
                if (localeArg != null) {
                    val normalized = localeArg.trim().lowercase()
                    locale = when (normalized) {
                        "all", "world", "global", "*" -> DEFAULT_LOCALE
                        "auto", "system" -> Locale.getDefault()
                        else -> Locale.forLanguageTag(localeArg.replace('_', '-'))
                    }
                }
            }
            "--result" -> resultPath = args.getOrNull(++index)
            "--timeout-seconds" -> timeoutSeconds = args.getOrNull(++index)?.toLongOrNull() ?: timeoutSeconds
            "--download-retries" -> downloadRetries = args.getOrNull(++index)?.toIntOrNull() ?: downloadRetries
            "--list-top-charts" -> listTopCharts = true
            "--chart" -> chartName = args.getOrNull(++index) ?: chartName
            "--chart-type" -> chartType = args.getOrNull(++index) ?: chartType
            "--chart-limit" -> chartLimit = args.getOrNull(++index)?.toIntOrNull() ?: chartLimit
        }
        index++
    }

    if (!listTopCharts && (packageName.isNullOrBlank() || output.isNullOrBlank())) {
        return null
    }

    val effectivePackage = packageName ?: ""
    val outputFile = File(output ?: "unused.apk")
    val outputDirectory = if (!outputDir.isNullOrBlank()) {
        File(outputDir)
    } else {
        outputFile.parentFile ?: File(".")
    }

    return Config(
        packageName = effectivePackage,
        output = outputFile,
        outputDir = outputDirectory,
        versionCode = versionCode,
        dispenserUrl = dispenserUrl,
        dispenserUserAgent = dispenserUserAgent,
        devicePropsPath = deviceProps?.let { File(it) },
        locale = locale,
        resultPath = resultPath?.let { File(it) },
        userAgent = userAgent,
        timeoutSeconds = timeoutSeconds,
        downloadRetries = downloadRetries,
        listTopCharts = listTopCharts,
        chartName = chartName,
        chartType = chartType,
        chartLimit = chartLimit
    )
}

private fun usage(): String = """
Usage:
  aurora-downloader --package com.example.app --output /path/to/base.apk [options]

Options:
  --output-dir   Directory to store all downloaded files (defaults to output parent)
  --version-code Override version code from Play
  --dispenser-url Token dispenser URL (default: $DEFAULT_DISPENSER)
  --dispenser-user-agent User-Agent for dispenser auth (default: $DEFAULT_DISPENSER_USER_AGENT)
  --user-agent   User-Agent for Play requests (default: $DEFAULT_USER_AGENT)
  --device-props Path to device properties file
  --locale       Locale override (e.g. en_US, all)
  --result       Write JSON result summary to file
  --timeout-seconds Request timeout (default: 60)
  --download-retries Retries for APK downloads (default: 2)
  --list-top-charts Output package list from top charts (no download)
  --chart        Top chart name (TOP_SELLING_FREE, TOP_SELLING_PAID, TOP_GROSSING, MOVERS_SHAKERS)
  --chart-type   Top chart type (APPLICATION, GAME)
  --chart-limit  Limit number of packages (default: 200)
""".trimIndent()

private fun resolveChartValue(input: String): String {
    val raw = input.trim()
    if (raw.isEmpty()) return TopChartsContract.Chart.TOP_SELLING_FREE.value
    val normalized = raw.uppercase()
    TopChartsContract.Chart.values().firstOrNull { it.name == normalized }?.let { return it.value }
    return raw
}

private fun resolveChartType(input: String): String {
    val raw = input.trim()
    if (raw.isEmpty()) return TopChartsContract.Type.APPLICATION.value
    val normalized = raw.uppercase()
    TopChartsContract.Type.values().firstOrNull { it.name == normalized }?.let { return it.value }
    return raw
}

private fun loadProperties(path: File?): Properties {
    val properties = Properties()
    if (path != null && path.exists()) {
        FileInputStream(path).use { properties.load(it) }
        return properties
    }
    val stream = Thread.currentThread().contextClassLoader.getResourceAsStream("device.properties")
    if (stream != null) {
        stream.use { properties.load(it) }
    }
    return properties
}

private fun buildAnonymousAuth(
    json: Json,
    httpClient: AuroraHttpClient,
    dispenserUrl: String,
    properties: Properties,
    locale: Locale
): AuthData {
    val body = json.encodeToString(PropertiesSerializer, properties).toByteArray()
    val response = httpClient.postAuth(dispenserUrl, body)
    if (!response.isSuccessful) {
        val details = sanitizeDispenserResponse(json, String(response.responseBytes))
        throw IOException("Dispenser request failed: ${response.code}${details?.let { ": $it" } ?: ""}")
    }
    val auth = parseDispenserAuth(json, String(response.responseBytes))
    return AuthHelper.build(
        email = auth.email,
        token = auth.auth,
        tokenType = AuthHelper.Token.AUTH,
        isAnonymous = true,
        properties = properties,
        locale = locale
    )
}

private fun parseDispenserAuth(json: Json, body: String): DispenserAuth {
    val element = runCatching { json.parseToJsonElement(body) }.getOrNull()
    if (element is JsonObject) {
        val email = element["email"]?.jsonPrimitive?.contentOrNull
        val token = element["authToken"]?.jsonPrimitive?.contentOrNull
            ?: element["auth"]?.jsonPrimitive?.contentOrNull
        if (!email.isNullOrBlank() && !token.isNullOrBlank()) {
            return DispenserAuth(email = email, auth = token)
        }
        val error = element["error"]?.jsonPrimitive?.contentOrNull
            ?: element["message"]?.jsonPrimitive?.contentOrNull
            ?: element["detail"]?.jsonPrimitive?.contentOrNull
        if (!error.isNullOrBlank()) {
            throw IOException("Dispenser error: $error")
        }
    }
    val details = sanitizeDispenserResponse(json, body)
    throw IOException("Dispenser response missing auth token${details?.let { ": $it" } ?: ""}")
}

private fun sanitizeDispenserResponse(json: Json, body: String, limit: Int = 300): String? {
    val trimmed = body.trim()
    if (trimmed.isEmpty()) return null
    val element = runCatching { json.parseToJsonElement(trimmed) }.getOrNull()
    val sanitized = if (element is JsonObject) {
        val redacted = element.toMutableMap()
        listOf("authToken", "auth", "email").forEach { key ->
            if (redacted.containsKey(key)) {
                redacted[key] = JsonPrimitive("***")
            }
        }
        JsonObject(redacted).toString()
    } else {
        trimmed
    }
    return if (sanitized.length > limit) "${sanitized.take(limit)}..." else sanitized
}

private fun isRetryableError(error: Throwable): Boolean {
    if (error is SocketTimeoutException) return true
    if (error is SocketException && error.message?.contains("Socket closed", ignoreCase = true) == true) {
        return true
    }
    val message = error.message?.lowercase() ?: ""
    return message.contains("timeout")
}

private fun shouldRetryStatus(code: Int): Boolean {
    return code in setOf(408, 429, 500, 502, 503, 504)
}

private fun downloadFile(okHttpClient: OkHttpClient, url: String, output: File, retries: Int) {
    val request = Request.Builder().url(url).build()
    var attempt = 0
    var lastError: IOException? = null
    while (attempt <= retries) {
        try {
            okHttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    if (shouldRetryStatus(response.code) && attempt < retries) {
                        attempt++
                        Thread.sleep((attempt * 1000).toLong())
                        return@use
                    }
                    throw IOException("Failed to download $url: ${response.code}")
                }
                output.parentFile?.mkdirs()
                response.body.byteStream().use { input ->
                    FileOutputStream(output).use { outputStream ->
                        input.copyTo(outputStream)
                    }
                }
                return
            }
        } catch (exc: IOException) {
            lastError = exc
            if (attempt >= retries || !isRetryableError(exc)) {
                break
            }
            attempt++
            Thread.sleep((attempt * 1000).toLong())
        }
    }
    throw lastError ?: IOException("Failed to download $url")
}

private fun selectBaseFile(files: List<PlayFile>): PlayFile? {
    return files.firstOrNull { it.type == PlayFile.Type.BASE }
        ?: files.firstOrNull { it.name.contains("base", ignoreCase = true) }
        ?: files.firstOrNull()
}

private class AuroraHttpClient(
    private val okHttpClient: OkHttpClient,
    private val userAgent: String
) : IHttpClient {
    private val _responseCode = MutableStateFlow(100)
    override val responseCode: StateFlow<Int>
        get() = _responseCode.asStateFlow()

    override fun postAuth(url: String, body: ByteArray): com.aurora.gplayapi.data.models.PlayResponse {
        val headers = mapOf("User-Agent" to userAgent)
        val requestBody = body.toRequestBody("application/json".toMediaType(), 0, body.size)
        return request(url, headers, "POST", url, requestBody)
    }

    override fun getAuth(url: String) = get(url, mapOf("User-Agent" to userAgent))

    override fun post(url: String, headers: Map<String, String>, params: Map<String, String>) =
        request(url, headers, "POST", buildUrl(url, params).toString(), "".toRequestBody(null))

    override fun post(url: String, headers: Map<String, String>, body: ByteArray) =
        request(url, headers, "POST", url, body.toRequestBody())

    override fun get(url: String, headers: Map<String, String>) =
        request(url, headers, "GET", url, null)

    override fun get(url: String, headers: Map<String, String>, params: Map<String, String>) =
        request(url, headers, "GET", buildUrl(url, params).toString(), null)

    override fun get(url: String, headers: Map<String, String>, paramString: String) =
        request(url, headers, "GET", "$url$paramString", null)

    private fun request(
        url: String,
        headers: Map<String, String>,
        method: String,
        resolvedUrl: String,
        body: RequestBody?
    ): com.aurora.gplayapi.data.models.PlayResponse {
        _responseCode.value = 0
        val request = Request(
            url = resolvedUrl.toHttpUrl(),
            headers = ensureUserAgent(headers).toHeaders(),
            method = method,
            body = body
        )
        val response = okHttpClient.newCall(request).execute()
        return com.aurora.gplayapi.data.models.PlayResponse(
            isSuccessful = response.isSuccessful,
            code = response.code,
            responseBytes = response.body.bytes(),
            errorString = if (!response.isSuccessful) response.message else String()
        ).also {
            _responseCode.value = response.code
        }
    }

    private fun buildUrl(url: String, params: Map<String, String>): HttpUrl {
        val urlBuilder = url.toHttpUrl().newBuilder()
        params.forEach { urlBuilder.addQueryParameter(it.key, it.value) }
        return urlBuilder.build()
    }

    private fun ensureUserAgent(headers: Map<String, String>): Map<String, String> {
        val hasUserAgent = headers.keys.any { it.equals("User-Agent", ignoreCase = true) }
        return if (hasUserAgent) headers else headers + ("User-Agent" to userAgent)
    }
}
