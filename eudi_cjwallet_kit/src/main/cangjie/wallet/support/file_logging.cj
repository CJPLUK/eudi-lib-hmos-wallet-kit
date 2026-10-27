/*
 * file_logging.cj
 *
 * EUDI Wallet Kit — FileLogging.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/FileLogging.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS FileLogging uses swift-log (LogHandler) with a file-backed output stream
 * (FileHandlerOutputStream + FileLogHandler).
 *
 * Cangjie mapping:
 *   - HarmonyOS does not provide direct file-descriptor log streams in the
 *     standard kit; Hilog is the canonical device logging facility.
 *   - FileLogging is adapted to Hilog-backed logging with a domain tag.
 *   - LogLevel enum mirrors swift-log's Logger.Level.
 *   - WalletLogger is the facade callers use (mirrors iOS Logger instance).
 *   - FileLogging.makeLogger() is a factory method matching the iOS pattern.
 *   - In production, callers may redirect logs to a file via HiLog's appended
 *     file sink (a kit.PerformanceAnalysisKit concern); this class stays thin.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

// ===========================================================================
// LogLevel
// ===========================================================================

/**
 * Logging severity levels.
 *
 * Mirrors swift-log Logger.Level values.
 */
public enum LogLevel {
    | Trace
    | Debug
    | Info
    | Notice
    | Warning
    | Error
    | Critical

    /** Priority order (higher = more severe). */
    public func severity(): Int64 {
        match (this) {
            case Trace    => return 0
            case Debug    => return 1
            case Info     => return 2
            case Notice   => return 3
            case Warning  => return 4
            case Error    => return 5
            case Critical => return 6
        }
    }

    /** Short string for formatting log messages. */
    public func label(): String {
        match (this) {
            case Trace    => return "TRACE"
            case Debug    => return "DEBUG"
            case Info     => return "INFO"
            case Notice   => return "NOTICE"
            case Warning  => return "WARN"
            case Error    => return "ERROR"
            case Critical => return "CRITICAL"
        }
    }
}

// ===========================================================================
// WalletLogHandler — Hilog-backed log handler
// ===========================================================================

/**
 * Log handler that routes messages to Hilog.
 *
 * Mirrors iOS FileLogHandler (LogHandler).
 *
 * Each log message is prefixed with [label] for filtering in Hilog output.
 * logLevel controls the minimum severity threshold; messages below the level
 * are silently discarded.
 */
public class WalletLogHandler {
    /** Hilog domain tag for this handler. */
    public let domain: String

    /** Minimum log level to emit. */
    public var logLevel: LogLevel

    /**
     * Construct a WalletLogHandler.
     *
     * @param domain    Hilog domain tag (up to 32 ASCII characters).
     * @param logLevel  Minimum severity (default: Debug in debug builds).
     */
    public init(domain!: String, logLevel!: LogLevel) {
        this.domain = domain
        this.logLevel = logLevel
    }

    /**
     * Emit a log message if `level` meets the threshold.
     *
     * Mirrors swift-log LogHandler.log(level:message:metadata:source:file:function:line:).
     *
     * @param level   Severity of the message.
     * @param message Human-readable log message.
     * @param source  Optional subsystem label (appended in brackets).
     */
    public func log(level!: LogLevel, message!: String, source!: ?String): Unit {
        if (level.severity() < logLevel.severity()) {
            return
        }
        let prefix = match (source) {
            case Some(s) => "[" + domain + "][" + s + "] "
            case None    => "[" + domain + "] "
        }
        let full = prefix + message
        match (level) {
            case LogLevel.Trace    => Hilog.debug(0, domain, full)
            case LogLevel.Debug    => Hilog.debug(0, domain, full)
            case LogLevel.Info     => Hilog.info(0, domain, full)
            case LogLevel.Notice   => Hilog.info(0, domain, full)
            case LogLevel.Warning  => Hilog.warn(0, domain, full)
            case LogLevel.Error    => Hilog.error(0, domain, full)
            case LogLevel.Critical => Hilog.fatal(0, domain, full)
        }
    }
}

// ===========================================================================
// WalletLogger — facade for callers
// ===========================================================================

/**
 * Structured logger for EUDI wallet operations.
 *
 * Wraps WalletLogHandler and provides convenience methods for each log level.
 *
 * Mirrors iOS `Logger` instance used in EudiWallet and supporting services.
 *
 * Usage:
 *   let logger = WalletLogger(label: "EudiWallet")
 *   logger.info("Wallet initialized")
 *   logger.error("Document load failed: " + err)
 */
public class WalletLogger {
    private let handler: WalletLogHandler

    /**
     * Create a WalletLogger with the given label (Hilog domain tag).
     * Default log level is Info.
     */
    public init(label!: String) {
        handler = WalletLogHandler(domain: label, logLevel: LogLevel.Info)
    }

    /**
     * Create a WalletLogger with explicit label and level.
     */
    public init(label!: String, level!: LogLevel) {
        handler = WalletLogHandler(domain: label, logLevel: level)
    }

    /** Current minimum log level. */
    public prop logLevel: LogLevel {
        get() { handler.logLevel }
    }

    /** Update the minimum log level. */
    public func setLogLevel(level: LogLevel): Unit {
        handler.logLevel = level
    }

    public func trace(message: String): Unit {
        handler.log(level: LogLevel.Trace, message: message, source: None)
    }

    public func trace(message: String, source: String): Unit {
        handler.log(level: LogLevel.Trace, message: message, source: Some(source))
    }

    public func debug(message: String): Unit {
        handler.log(level: LogLevel.Debug, message: message, source: None)
    }

    public func debug(message: String, source: String): Unit {
        handler.log(level: LogLevel.Debug, message: message, source: Some(source))
    }

    public func info(message: String): Unit {
        handler.log(level: LogLevel.Info, message: message, source: None)
    }

    public func info(message: String, source: String): Unit {
        handler.log(level: LogLevel.Info, message: message, source: Some(source))
    }

    public func notice(message: String): Unit {
        handler.log(level: LogLevel.Notice, message: message, source: None)
    }

    public func warning(message: String): Unit {
        handler.log(level: LogLevel.Warning, message: message, source: None)
    }

    public func warning(message: String, source: String): Unit {
        handler.log(level: LogLevel.Warning, message: message, source: Some(source))
    }

    public func error(message: String): Unit {
        handler.log(level: LogLevel.Error, message: message, source: None)
    }

    public func error(message: String, source: String): Unit {
        handler.log(level: LogLevel.Error, message: message, source: Some(source))
    }

    public func critical(message: String): Unit {
        handler.log(level: LogLevel.Critical, message: message, source: None)
    }
}

// ===========================================================================
// FileLogging — factory mirroring iOS FileLogging type
// ===========================================================================

/**
 * Factory for creating WalletLogger instances.
 *
 * Mirrors iOS `enum FileLogging` static factory.
 *
 * In the iOS implementation, FileLogging sets up a LoggingSystem bootstrap
 * with a file-backed log handler.  In Cangjie/HarmonyOS, Hilog is the
 * canonical log sink; this factory creates WalletLogger instances with
 * consistent configuration.
 *
 * Usage:
 *   let logger = FileLogging.makeLogger(label: "EudiWallet")
 *   logger.info("ready")
 */
public class FileLogging {

    private init() {}

    /**
     * Create a WalletLogger for the given label.
     *
     * @param label   Identifies the subsystem (used as Hilog domain tag).
     * @param level   Minimum log level (default: Info).
     * @return Configured WalletLogger.
     */
    public static func makeLogger(label: String, level: LogLevel): WalletLogger {
        return WalletLogger(label: label, level: level)
    }

    /** Convenience factory with default level (Info). */
    public static func makeLogger(label: String): WalletLogger {
        return WalletLogger(label: label)
    }
}
