export namespace main {

	export class AppUpdateAsset {
	    name: string;
	    downloadUrl: string;
	    sizeBytes: number;
	    contentType: string;

	    static createFrom(source: any = {}) {
	        return new AppUpdateAsset(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.downloadUrl = source["downloadUrl"];
	        this.sizeBytes = source["sizeBytes"];
	        this.contentType = source["contentType"];
	    }
	}
	export class AppUpdateStatus {
	    currentVersion: string;
	    currentVersionDisplay: string;
	    currentVersionSource: string;
	    currentExecutable: string;
	    localHash: string;
	    repo: string;
	    authMode: string;
	    checkedAt: string;
	    apiUrl: string;
	    hasUpdate: boolean;
	    upToDate: boolean;
	    hashMismatch: boolean;
	    latestTag: string;
	    latestName: string;
	    latestPublishedAt: string;
	    releaseUrl: string;
	    releaseNotes: string;
	    selectedAsset?: AppUpdateAsset;
	    canInstall: boolean;
	    message: string;

	    static createFrom(source: any = {}) {
	        return new AppUpdateStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentVersion = source["currentVersion"];
	        this.currentVersionDisplay = source["currentVersionDisplay"];
	        this.currentVersionSource = source["currentVersionSource"];
	        this.currentExecutable = source["currentExecutable"];
	        this.localHash = source["localHash"];
	        this.repo = source["repo"];
	        this.authMode = source["authMode"];
	        this.checkedAt = source["checkedAt"];
	        this.apiUrl = source["apiUrl"];
	        this.hasUpdate = source["hasUpdate"];
	        this.upToDate = source["upToDate"];
	        this.hashMismatch = source["hashMismatch"];
	        this.latestTag = source["latestTag"];
	        this.latestName = source["latestName"];
	        this.latestPublishedAt = source["latestPublishedAt"];
	        this.releaseUrl = source["releaseUrl"];
	        this.releaseNotes = source["releaseNotes"];
	        this.selectedAsset = this.convertValues(source["selectedAsset"], AppUpdateAsset);
	        this.canInstall = source["canInstall"];
	        this.message = source["message"];
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class desktopBackendBlob {
	    data_base64: string;
	    content_type: string;
	    filename?: string;
	    size: number;

	    static createFrom(source: any = {}) {
	        return new desktopBackendBlob(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.data_base64 = source["data_base64"];
	        this.content_type = source["content_type"];
	        this.filename = source["filename"];
	        this.size = source["size"];
	    }
	}
	export class desktopBackendProbe {
	    ready: boolean;
	    health_ok: boolean;
	    identity_ok: boolean;
	    capture_status_ok: boolean;
	    misc_package_dir?: string;
	    message?: string;

	    static createFrom(source: any = {}) {
	        return new desktopBackendProbe(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ready = source["ready"];
	        this.health_ok = source["health_ok"];
	        this.identity_ok = source["identity_ok"];
	        this.capture_status_ok = source["capture_status_ok"];
	        this.misc_package_dir = source["misc_package_dir"];
	        this.message = source["message"];
	    }
	}
	export class desktopC2DecryptRequest {
	    family: string;
	    scope?: Record<string, any>;
	    vshell?: Record<string, any>;
	    cs?: Record<string, any>;

	    static createFrom(source: any = {}) {
	        return new desktopC2DecryptRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.family = source["family"];
	        this.scope = source["scope"];
	        this.vshell = source["vshell"];
	        this.cs = source["cs"];
	    }
	}
	export class desktopHuntingRuntimeConfig {
	    prefixes: string[];
	    yara_enabled: boolean;
	    yara_bin: string;
	    yara_rules: string;
	    yara_timeout_ms: number;

	    static createFrom(source: any = {}) {
	        return new desktopHuntingRuntimeConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.prefixes = source["prefixes"];
	        this.yara_enabled = source["yara_enabled"];
	        this.yara_bin = source["yara_bin"];
	        this.yara_rules = source["yara_rules"];
	        this.yara_timeout_ms = source["yara_timeout_ms"];
	    }
	}
	export class desktopMCPConfig {
	    enabled: boolean;

	    static createFrom(source: any = {}) {
	        return new desktopMCPConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	    }
	}
	export class desktopSMB3RandomSessionKeyRequest {
	    username: string;
	    domain: string;
	    ntlm_hash: string;
	    nt_proof_str: string;
	    encrypted_session_key: string;

	    static createFrom(source: any = {}) {
	        return new desktopSMB3RandomSessionKeyRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.domain = source["domain"];
	        this.ntlm_hash = source["ntlm_hash"];
	        this.nt_proof_str = source["nt_proof_str"];
	        this.encrypted_session_key = source["encrypted_session_key"];
	    }
	}
	export class desktopStreamDecodeRequest {
	    decoder: string;
	    payload: string;
	    options?: Record<string, any>;

	    static createFrom(source: any = {}) {
	        return new desktopStreamDecodeRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.decoder = source["decoder"];
	        this.payload = source["payload"];
	        this.options = source["options"];
	    }
	}
	export class desktopStreamPayloadPatch {
	    index: number;
	    body: string;

	    static createFrom(source: any = {}) {
	        return new desktopStreamPayloadPatch(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.index = source["index"];
	        this.body = source["body"];
	    }
	}
	export class desktopTLSConfig {
	    ssl_key_log_file: string;
	    rsa_private_key: string;
	    target_ip_port: string;

	    static createFrom(source: any = {}) {
	        return new desktopTLSConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ssl_key_log_file = source["ssl_key_log_file"];
	        this.rsa_private_key = source["rsa_private_key"];
	        this.target_ip_port = source["target_ip_port"];
	    }
	}
	export class desktopToolAllowedDirs {
	    dirs: string[];

	    static createFrom(source: any = {}) {
	        return new desktopToolAllowedDirs(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dirs = source["dirs"];
	    }
	}
	export class desktopToolRuntimeConfig {
	    tshark_path: string;
	    tshark_allowed_dirs?: string[];
	    ffmpeg_path: string;
	    ffmpeg_allowed_dirs?: string[];
	    python_path: string;
	    python_allowed_dirs?: string[];
	    vosk_model_path: string;
	    yara_enabled: boolean;
	    yara_bin: string;
	    yara_allowed_dirs?: string[];
	    yara_rules: string;
	    yara_timeout_ms: number;

	    static createFrom(source: any = {}) {
	        return new desktopToolRuntimeConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tshark_path = source["tshark_path"];
	        this.tshark_allowed_dirs = source["tshark_allowed_dirs"];
	        this.ffmpeg_path = source["ffmpeg_path"];
	        this.ffmpeg_allowed_dirs = source["ffmpeg_allowed_dirs"];
	        this.python_path = source["python_path"];
	        this.python_allowed_dirs = source["python_allowed_dirs"];
	        this.vosk_model_path = source["vosk_model_path"];
	        this.yara_enabled = source["yara_enabled"];
	        this.yara_bin = source["yara_bin"];
	        this.yara_allowed_dirs = source["yara_allowed_dirs"];
	        this.yara_rules = source["yara_rules"];
	        this.yara_timeout_ms = source["yara_timeout_ms"];
	    }
	}
	export class desktopWebviewSmokeConfig {
	    enabled: boolean;
	    capture_path?: string;
	    misc_package_dir?: string;
	    generic_ipc_disable_experiment?: boolean;

	    static createFrom(source: any = {}) {
	        return new desktopWebviewSmokeConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.capture_path = source["capture_path"];
	        this.misc_package_dir = source["misc_package_dir"];
	        this.generic_ipc_disable_experiment = source["generic_ipc_disable_experiment"];
	    }
	}
	export class desktopWinRMDecryptRequest {
	    port: number;
	    auth_mode: string;
	    password: string;
	    nt_hash: string;
	    preview_lines: number;
	    include_error_frames: boolean;
	    extract_command_output: boolean;

	    static createFrom(source: any = {}) {
	        return new desktopWinRMDecryptRequest(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.auth_mode = source["auth_mode"];
	        this.password = source["password"];
	        this.nt_hash = source["nt_hash"];
	        this.preview_lines = source["preview_lines"];
	        this.include_error_frames = source["include_error_frames"];
	        this.extract_command_output = source["extract_command_output"];
	    }
	}
	export class openCaptureDialogResult {
	    filePath: string;
	    fileSize: number;
	    fileName: string;

	    static createFrom(source: any = {}) {
	        return new openCaptureDialogResult(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filePath = source["filePath"];
	        this.fileSize = source["fileSize"];
	        this.fileName = source["fileName"];
	    }
	}

}
