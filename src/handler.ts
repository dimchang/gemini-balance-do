import { DurableObject } from 'cloudflare:workers';
import { isAdminAuthenticated } from './auth';

class HttpError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = this.constructor.name;
		this.status = status;
	}
}

const fixCors = ({ headers, status, statusText }: { headers?: HeadersInit; status?: number; statusText?: string }) => {
	const newHeaders = new Headers(headers);
	newHeaders.set('Access-Control-Allow-Origin', '*');
	newHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
	newHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-goog-api-key');
	return { headers: newHeaders, status, statusText };
};

const BASE_URL = 'https://generativelanguage.googleapis.com';
const API_VERSION = 'v1beta';
const API_CLIENT = 'genai-js/0.21.0';

const makeHeaders = (apiKey: string, more?: Record<string, string>) => ({
	'x-goog-api-client': API_CLIENT,
	...(apiKey && { 'x-goog-api-key': apiKey }),
	...more,
});

/** A Durable Object's behavior is defined in an exported Javascript class */
export class LoadBalancer extends DurableObject {
	env: Env;
	/**
	 * The constructor is invoked once upon creation of the Durable Object, i.e. the first call to
	 * 	`DurableObjectStub::get` for a given identifier (no-op constructors can be omitted)
	 *
	 * @param ctx - The interface for interacting with Durable Object state
	 * @param env - The interface to reference bindings declared in wrangler.jsonc
	 */
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.env = env;
		// Initialize the database schema upon first creation.
		this.ctx.storage.sql.exec(
			'CREATE TABLE IF NOT EXISTS api_keys (api_key TEXT PRIMARY KEY, total_calls INTEGER DEFAULT 0)'
		);
		this.ctx.storage.sql.exec(
			'CREATE TABLE IF NOT EXISTS api_key_usage_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, api_key TEXT, timestamp INTEGER)'
		);
		// Migration to add total_calls column if it doesn't exist
		try {
			this.ctx.storage.sql.exec('ALTER TABLE api_keys ADD COLUMN total_calls INTEGER DEFAULT 0');
		} catch (e: any) {
			// Ignore error if column already exists
			if (!e.message.includes('duplicate column name')) {
				console.error('Migration failed:', e);
			}
		}
	}

	async fetch(request: Request): Promise<Response> {
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				status: 204,
				headers: fixCors({}).headers,
			});
		}
		const url = new URL(request.url);
		const pathname = url.pathname;

		// 静态资源直接放行
		if (pathname === '/favicon.ico' || pathname === '/robots.txt') {
			return new Response('', { status: 204 });
		}

		// 处理获取下一个API密钥的请求
		if (pathname === '/api/next-key' && request.method === 'GET') {
			if (!isAdminAuthenticated(request, this.env.HOME_ACCESS_KEY)) {
				return new Response(JSON.stringify({ error: 'Unauthorized' }), {
					status: 401,
					headers: fixCors({ headers: { 'Content-Type': 'application/json' } }).headers,
				});
			}
			try {
				const key = await this.getNextApiKeyInRotation();
				if (!key) {
					return new Response(JSON.stringify({ error: '没有可用的API密钥' }), {
						status: 500,
						headers: { 'Content-Type': 'application/json', ...fixCors({}).headers },
					});
				}
				return new Response(JSON.stringify({ key }), {
					status: 200,
					headers: { 'Content-Type': 'application/json', ...fixCors({}).headers },
				});
			} catch (error: any) {
				console.error('获取轮询API密钥失败:', error);
				return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
					status: 500,
					headers: { 'Content-Type': 'application/json', ...fixCors({}).headers },
				});
			}
		}

		// 管理 API 权限校验（使用 HOME_ACCESS_KEY）
		if (
			(pathname === '/api/keys' && ['POST', 'GET', 'DELETE'].includes(request.method)) ||
			(pathname === '/api/keys/check' && request.method === 'GET') ||
			(pathname === '/api/keys/stats' && request.method === 'GET') ||
			(pathname === '/api/keys/all' && request.method === 'DELETE')
		) {
			if (!isAdminAuthenticated(request, this.env.HOME_ACCESS_KEY)) {
				return new Response(JSON.stringify({ error: 'Unauthorized' }), {
					status: 401,
					headers: fixCors({ headers: { 'Content-Type': 'application/json' } }).headers,
				});
			}
			if (pathname === '/api/keys' && request.method === 'POST') {
				return this.handleApiKeys(request);
			}
			if (pathname === '/api/keys' && request.method === 'GET') {
				return this.getAllApiKeys();
			}
			if (pathname === '/api/keys' && request.method === 'DELETE') {
				return this.handleDeleteApiKeys(request);
			}
			if (pathname === '/api/keys/all' && request.method === 'DELETE') {
				return this.handleDeleteAllKeys();
			}
			if (pathname === '/api/keys/check' && request.method === 'GET') {
				return this.handleApiKeysCheck();
			}
			if (pathname === '/api/keys/stats' && request.method === 'GET') {
				return this.handleApiKeysStats();
			}
		}

		const search = url.search;

		// OpenAI compatible routes
		if (
			pathname.endsWith('/chat/completions') ||
			pathname.endsWith('/completions') ||
			pathname.endsWith('/embeddings') ||
			pathname.endsWith('/v1/models')
		) {
			return this.handleOpenAI(request);
		}

		// Direct Gemini proxy
		const authKey = this.env.AUTH_KEY;

		let targetUrl = `${BASE_URL}${pathname}${search}`;

		if (this.env.FORWARD_CLIENT_KEY_ENABLED) {
			return this.forwardRequestWithLoadBalancing(targetUrl, request);
		}

		if (authKey) {
			let isAuthorized = false;
			// Check key in query parameters
			if (search.includes('key=')) {
				const urlObj = new URL(targetUrl);
				const requestKey = urlObj.searchParams.get('key');
				if (requestKey && requestKey === authKey) {
					isAuthorized = true;
				}
			} else {
				// Check x-goog-api-key in headers
				const requestKey = request.headers.get('x-goog-api-key');
				if (requestKey && requestKey === authKey) {
					isAuthorized = true;
				}
			}

			if (!isAuthorized) {
				return new Response('Unauthorized', { status: 401, headers: fixCors({}).headers });
			}
		}
		// If authKey is not set, or if it was authorized, proceed to forward with load balancing.
		return this.forwardRequestWithLoadBalancing(targetUrl, request);
	}

	async forwardRequest(targetUrl: string, request: Request, headers: Headers): Promise<Response> {
		console.log(`Request Sending to Gemini: ${targetUrl}`);

		const response = await fetch(targetUrl, {
			method: request.method,
			headers: headers,
			body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
		});

		console.log('Call Gemini Success');

		const responseHeaders = new Headers(response.headers);
		responseHeaders.set('Access-Control-Allow-Origin', '*');
		responseHeaders.delete('transfer-encoding');
		responseHeaders.delete('connection');
		responseHeaders.delete('keep-alive');
		responseHeaders.delete('content-encoding');
		responseHeaders.set('Referrer-Policy', 'no-referrer');

		return new Response(response.body, {
			status: response.status,
			headers: responseHeaders,
		});
	}

	// 对请求进行负载均衡，随机分发key
	private async forwardRequestWithLoadBalancing(targetUrl: string, request: Request): Promise<Response> {
		try {
			let headers = new Headers();
			const url = new URL(targetUrl);

			// Forward content-type header
			if (request.headers.has('content-type')) {
				headers.set('content-type', request.headers.get('content-type')!);
			}

			if (this.env.FORWARD_CLIENT_KEY_ENABLED) {
				return this.forwardRequest(url.toString(), request, headers);
			}
			const apiKey = await this.getNextApiKeyInRotation();
			if (!apiKey) {
				return new Response('No API keys configured in the load balancer.', { status: 500 });
			}

			url.searchParams.set('key', apiKey);
			headers.set('x-goog-api-key', apiKey);
			return this.forwardRequest(url.toString(), request, headers);
		} catch (error) {
			console.error('Failed to fetch:', error);
			return new Response('Internal Server Error\n' + error, {
				status: 500,
				headers: { 'Content-Type': 'text/plain' },
			});
		}
	}

	async handleModels(apiKey: string) {
		const response = await fetch(`${BASE_URL}/${API_VERSION}/models`, {
			headers: makeHeaders(apiKey),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			const { models } = JSON.parse(await response.text());
			responseBody = JSON.stringify(
				{
					object: 'list',
					data: models.map(({ name }: any) => ({
						id: name.replace('models/', ''),
						object: 'model',
						created: 0,
						owned_by: '',
					})),
				},
				null,
				'  '
			);
		}
		return new Response(responseBody, fixCors(response));
	}

	async handleEmbeddings(req: any, apiKey: string) {
		const DEFAULT_EMBEDDINGS_MODEL = 'text-embedding-004';

		if (typeof req.model !== 'string') {
			throw new HttpError('model is not specified', 400);
		}

		let model;
		if (req.model.startsWith('models/')) {
			model = req.model;
		} else {
			if (!req.model.startsWith('gemini-')) {
				req.model = DEFAULT_EMBEDDINGS_MODEL;
			}
			model = 'models/' + req.model;
		}

		if (!Array.isArray(req.input)) {
			req.input = [req.input];
		}

		const response = await fetch(`${BASE_URL}/${API_VERSION}/${model}:batchEmbedContents`, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify({
				requests: req.input.map((text: string) => ({
					model,
					content: { parts: { text } },
					outputDimensionality: req.dimensions,
				})),
			}),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			const { embeddings } = JSON.parse(await response.text());
			responseBody = JSON.stringify(
				{
					object: 'list',
					data: embeddings.map(({ values }: any, index: number) => ({
						object: 'embedding',
						index,
						embedding: values,
					})),
					model: req.model,
				},
				null,
				'  '
			);
		}
		return new Response(responseBody, fixCors(response));
	}

	async handleCompletions(req: any, apiKey: string) {
		const DEFAULT_MODEL = 'gemini-2.5-flash';
		let model = DEFAULT_MODEL;

		switch (true) {
			case typeof req.model !== 'string':
				break;
			case req.model.startsWith('models/'):
				model = req.model.substring(7);
				break;
			case req.model.startsWith('gemini-'):
			case req.model.startsWith('gemma-'):
			case req.model.startsWith('learnlm-'):
				model = req.model;
		}

		let body = await this.transformRequest(req);
		const extra = req.extra_body?.google;

		if (extra) {
			if (extra.safety_settings) {
				body.safetySettings = extra.safety_settings;
			}
			if (extra.cached_content) {
				body.cachedContent = extra.cached_content;
			}
			if (extra.thinking_config) {
				body.generationConfig.thinkingConfig = extra.thinking_config;
			}
		}

		switch (true) {
			case model.endsWith(':search'):
				model = model.substring(0, model.length - 7);
			case req.model.endsWith('-search-preview'):
			case req.tools?.some((tool: any) => tool.function?.name === 'googleSearch'):
				body.tools = body.tools || [];
				body.tools.push({ function_declarations: [{ name: 'googleSearch', parameters: {} }] });
		}

		const TASK = req.stream ? 'streamGenerateContent' : 'generateContent';
		let url = `${BASE_URL}/${API_VERSION}/models/${model}:${TASK}`;
		if (req.stream) {
			url += '?alt=sse';
		}

		const response = await fetch(url, {
			method: 'POST',
			headers: makeHeaders(apiKey, { 'Content-Type': 'application/json' }),
			body: JSON.stringify(body),
		});

		let responseBody: BodyInit | null = response.body;
		if (response.ok) {
			let id = 'chatcmpl-' + this.generateId();
			const shared = {};

			if (req.stream) {
				responseBody = response
					.body!.pipeThrough(new TextDecoderStream())
					.pipeThrough(
						new TransformStream({
							transform: this.parseStream,
							flush: this.parseStreamFlush,
							buffer: '',
							shared,
						} as any)
					)
					.pipeThrough(
						new TransformStream({
							transform: this.toOpenAiStream,
							flush: this.toOpenAiStreamFlush,
							streamIncludeUsage: req.stream_options?.include_usage,
							model,
							id,
							last: [],
							shared,
						} as any)
					)
					.pipeThrough(new TextEncoderStream());
			} else {
				let body: any = await response.text();
				try {
					body = JSON.parse(body);
					if (!body.candidates) {
						throw new Error('Invalid completion object');
					}
				} catch (err) {
					console.error('Error parsing response:', err);
					return new Response(JSON.stringify({ error: 'Failed to parse response' }), {
						...fixCors(response),
						status: 500,
					});
				}
				responseBody = this.processCompletionsResponse(body, model, id);
			}
		}
		return new Response(responseBody, fixCors(response));
	}

	// 辅助方法
	private generateId(): string {
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const randomChar = () => characters[Math.floor(Math.random() * characters.length)];
		return Array.from({ length: 29 }, randomChar).join('');
	}

	private async transformRequest(req: any) {
		const harmCategory = [
			'HARM_CATEGORY_HATE_SPEECH',
			'HARM_CATEGORY_SEXUALLY_EXPLICIT',
			'HARM_CATEGORY_DANGEROUS_CONTENT',
			'HARM_CATEGORY_HARASSMENT',
			'HARM_CATEGORY_CIVIC_INTEGRITY',
		];

		const safetySettings = harmCategory.map((category) => ({
			category,
			threshold: 'BLOCK_NONE',
		}));

		return {
			...(await this.transformMessages(req.messages)),
			safetySettings,
			generationConfig: this.transformConfig(req),
			...this.transformTools(req),
			cachedContent: undefined as any,
		};
	}

	private transformConfig(req: any) {
		const fieldsMap: Record<string, string> = {
			frequency_penalty: 'frequencyPenalty',
			max_completion_tokens: 'maxOutputTokens',
			max_tokens: 'maxOutputTokens',
			n: 'candidateCount',
			presence_penalty: 'presencePenalty',
			seed: 'seed',
			stop: 'stopSequences',
			temperature: 'temperature',
			top_k: 'topK',
			top_p: 'topP',
		};

		const thinkingBudgetMap: Record<string, number> = {
			low: 1024,
			medium: 8192,
			high: 24576,
		};

		let cfg: any = {};
		for (let key in req) {
			const matchedKey = fieldsMap[key];
			if (matchedKey) {
				cfg[matchedKey] = req[key];
			}
		}

		if (req.response_format) {
			switch (req.response_format.type) {
				case 'json_schema':
					cfg.responseSchema = req.response_format.json_schema?.schema;
					if (cfg.responseSchema && 'enum' in cfg.responseSchema) {
						cfg.responseMimeType = 'text/x.enum';
						break;
					}
				case 'json_object':
					cfg.responseMimeType = 'application/json';
					break;
				case 'text':
					cfg.responseMimeType = 'text/plain';
					break;
				default:
					throw new HttpError('Unsupported response_format.type', 400);
			}
		}
		if (req.reasoning_effort) {
			cfg.thinkingConfig = { thinkingBudget: thinkingBudgetMap[req.reasoning_effort] };
		}

		return cfg;
	}

	private async transformMessages(messages: any[]) {
		if (!messages) {
			return {};
		}

		const contents: any[] = [];
		let system_instruction;

		for (const item of messages) {
			switch (item.role) {
				case 'system':
					system_instruction = { parts: await this.transformMsg(item) };
					continue;
				case 'assistant':
					item.role = 'model';
					break;
				case 'user':
					break;
				default:
					throw new HttpError(`Unknown message role: "${item.role}"`, 400);
			}

			if (system_instruction) {
				if (!contents[0]?.parts.some((part: any) => part.text)) {
					contents.unshift({ role: 'user', parts: { text: ' ' } });
				}
			}

			contents.push({
				role: item.role,
				parts: await this.transformMsg(item),
			});
		}

		return { system_instruction, contents };
	}

	private async transformMsg({ content }: any) {
		const parts = [];
		if (!Array.isArray(content)) {
			parts.push({ text: content });
			return parts;
		}

		for (const item of content) {
			switch (item.type) {
				case 'text':
					parts.push({ text: item.text });
					break;
				case 'image_url':
					parts.push(await this.parseImg(item.image_url.url));
					break;
				case 'input_audio':
					parts.push({
						inlineData: {
							mimeType: 'audio/' + item.input_audio.format,
							data: item.input_audio.data,
						},
					});
					break;
				default:
					throw new HttpError(`Unknown "content" item type: "${item.type}"`, 400);
			}
		}

		if (content.every((item) => item.type === 'image_url')) {
			parts.push({ text: '' }); // to avoid "Unable to submit request because it must have a text parameter"
		}
		return parts;
	}
	private async parseImg(url: any) {
		let mimeType, data;
		if (url.startsWith('http://') || url.startsWith('https://')) {
			try {
				const response = await fetch(url);
				if (!response.ok) {
					throw new Error(`${response.status} ${response.statusText} (${url})`);
				}
				mimeType = response.headers.get('content-type');
				data = Buffer.from(await response.arrayBuffer()).toString('base64');
			} catch (err) {
				throw new Error('Error fetching image: ' + (err as Error).message);
			}
		} else {
			const match = url.match(/^data:(?<mimeType>.*?)(;base64)?,(?<data>.*)$/);
			if (!match) {
				throw new HttpError('Invalid image data: ' + url, 400);
			}
			({ mimeType, data } = match.groups);
		}
		return {
			inlineData: {
				mimeType,
				data,
			},
		};
	}

	private adjustSchema(schema: any) {
		const obj = schema[schema.type];
		delete obj.strict;
		return this.adjustProps(schema);
	}

	private adjustProps = (schemaPart: any) => {
		if (typeof schemaPart !== 'object' || schemaPart === null) {
			return;
		}
		if (Array.isArray(schemaPart)) {
			schemaPart.forEach(this.adjustProps);
		} else {
			if (schemaPart.type === 'object' && schemaPart.properties && schemaPart.additionalProperties === false) {
				delete schemaPart.additionalProperties;
			}
			Object.values(schemaPart).forEach(this.adjustProps);
		}
	};

	private transformTools(req: any) {
		let tools, tool_config;
		if (req.tools) {
			const funcs = req.tools.filter((tool: any) => tool.type === 'function' && tool.function?.name !== 'googleSearch');
			if (funcs.length > 0) {
				funcs.forEach((tool: any) => this.adjustSchema(tool)); 
				//funcs.forEach(this.adjustSchema);
				tools = [{ function_declarations: funcs.map((schema: any) => schema.function) }];
			}
		}
		if (req.tool_choice) {
			const allowed_function_names = req.tool_choice?.type === 'function' ? [req.tool_choice?.function?.name] : undefined;
			if (allowed_function_names || typeof req.tool_choice === 'string') {
				tool_config = {
					function_calling_config: {
						mode: allowed_function_names ? 'ANY' : req.tool_choice.toUpperCase(),
						allowed_function_names,
					},
				};
			}
		}
		return { tools, tool_config };
	}

	private processCompletionsResponse(data: any, model: string, id: string) {
		const reasonsMap: Record<string, string> = {
			STOP: 'stop',
			MAX_TOKENS: 'length',
			SAFETY: 'content_filter',
			RECITATION: 'content_filter',
		};

		const transformCandidatesMessage = (cand: any) => {
			const message = { role: 'assistant', content: [] as string[] };
			for (const part of cand.content?.parts ?? []) {
				if (part.text) {
					message.content.push(part.text);
				}
			}

			return {
				index: cand.index || 0,
				message: {
					...message,
					content: message.content.join('') || null,
				},
				logprobs: null,
				finish_reason: reasonsMap[cand.finishReason] || cand.finishReason,
			};
		};

		const obj = {
			id,
			choices: data.candidates.map(transformCandidatesMessage),
			created: Math.floor(Date.now() / 1000),
			model: data.modelVersion ?? model,
			object: 'chat.completion',
			usage: data.usageMetadata && {
				completion_tokens: data.usageMetadata.candidatesTokenCount,
				prompt_tokens: data.usageMetadata.promptTokenCount,
				total_tokens: data.usageMetadata.totalTokenCount,
			},
		};

		return JSON.stringify(obj);
	}

	// 流处理方法
	private parseStream(this: any, chunk: string, controller: any) {
		this.buffer += chunk;
		const lines = this.buffer.split('\n');
		this.buffer = lines.pop()!;

		for (const line of lines) {
			if (line.startsWith('data: ')) {
				const data = line.substring(6);
				if (data.startsWith('{')) {
					controller.enqueue(JSON.parse(data));
				}
			}
		}
	}

	private parseStreamFlush(this: any, controller: any) {
		if (this.buffer) {
			try {
				controller.enqueue(JSON.parse(this.buffer));
				this.shared.is_buffers_rest = true;
			} catch (e) {
				console.error('Error parsing remaining buffer:', e);
			}
		}
	}

	private toOpenAiStream(this: any, line: any, controller: any) {
		const reasonsMap: Record<string, string> = {
			STOP: 'stop',
			MAX_TOKENS: 'length',
			SAFETY: 'content_filter',
			RECITATION: 'content_filter',
		};

		const { candidates, usageMetadata } = line;
		if (usageMetadata) {
			this.shared.usage = {
				completion_tokens: usageMetadata.candidatesTokenCount,
				prompt_tokens: usageMetadata.promptTokenCount,
				total_tokens: usageMetadata.totalTokenCount,
			};
		}

		if (candidates) {
			for (const cand of candidates) {
				const { index, content, finishReason } = cand;
				const { parts } = content;
				const text = parts.map((p: any) => p.text).join('');

				if (this.last[index] === undefined) {
					this.last[index] = '';
				}

				const lastText = this.last[index] || '';
				let delta = '';

				if (text.startsWith(lastText)) {
					delta = text.substring(lastText.length);
				} else {
					// Find the common prefix
					let i = 0;
					while (i < text.length && i < lastText.length && text[i] === lastText[i]) {
						i++;
					}
					// Send the rest of the new text as delta.
					// This might not be perfect for all clients, but it prevents data loss.
					delta = text.substring(i);
				}

				this.last[index] = text;

				const obj = {
					id: this.id,
					object: 'chat.completion.chunk',
					created: Math.floor(Date.now() / 1000),
					model: this.model,
					choices: [
						{
							index,
							delta: { content: delta },
							finish_reason: reasonsMap[finishReason] || finishReason,
						},
					],
				};
				controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
			}
		}
	}

	private toOpenAiStreamFlush(this: any, controller: any) {
		if (this.streamIncludeUsage && this.shared.usage) {
			const obj = {
				id: this.id,
				object: 'chat.completion.chunk',
				created: Math.floor(Date.now() / 1000),
				model: this.model,
				choices: [
					{
						index: 0,
						delta: {},
						finish_reason: 'stop',
					},
				],
				usage: this.shared.usage,
			};
			controller.enqueue(`data: ${JSON.stringify(obj)}\n\n`);
		}
		controller.enqueue('data: [DONE]\n\n');
	}
	// =================================================================================================
	// Admin API Handlers
	// =================================================================================================

	async handleDeleteAllKeys(): Promise<Response> {
		try {
			await this.ctx.storage.sql.exec('DELETE FROM api_keys');
			return new Response(JSON.stringify({ message: '所有API密钥已成功删除。' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('删除所有API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	async handleApiKeys(request: Request): Promise<Response> {
		try {
			const { keys } = (await request.json()) as { keys: string[] };
			if (!Array.isArray(keys) || keys.length === 0) {
				return new Response(JSON.stringify({ error: '请求体无效，需要一个包含key的非空数组。' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				});
			}

			for (const key of keys) {
				await this.ctx.storage.sql.exec('INSERT OR IGNORE INTO api_keys (api_key) VALUES (?)', key);
			}

			return new Response(JSON.stringify({ message: 'API密钥添加成功。' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('处理API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	async handleDeleteApiKeys(request: Request): Promise<Response> {
		try {
			const { keys } = (await request.json()) as { keys: string[] };
			if (!Array.isArray(keys) || keys.length === 0) {
				return new Response(JSON.stringify({ error: '请求体无效，需要一个包含key的非空数组。' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json' },
				});
			}

			const batchSize = 500;
			for (let i = 0; i < keys.length; i += batchSize) {
				const batch = keys.slice(i, i + batchSize);
				const placeholders = batch.map(() => '?').join(',');
				await this.ctx.storage.sql.exec(`DELETE FROM api_keys WHERE api_key IN (${placeholders})`, ...batch);
			}

			return new Response(JSON.stringify({ message: 'API密钥删除成功。' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('删除API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	async handleApiKeysCheck(): Promise<Response> {
		try {
			const results = await this.ctx.storage.sql.exec('SELECT api_key FROM api_keys').raw<any>();
			const keys = Array.from(results);
			console.log('keys: ', keys);

			const checkResults = await Promise.all(
				keys.map(async (key: string) => {
					console.log('checking key: ', key);
					try {
						const response = await fetch(`${BASE_URL}/${API_VERSION}/models?key=${key}`);
						return { key: key, valid: response.ok, error: response.ok ? null : await response.text() };
					} catch (e: any) {
						return { key: key, valid: false, error: e.message };
					}
				})
			);

			const invalidKeys = checkResults.filter((result) => !result.valid).map((result) => result.key);
			if (invalidKeys.length > 0) {
				console.log('InvalidKeys: ', JSON.stringify(invalidKeys));
				const batchSize = 500;
				for (let i = 0; i < invalidKeys.length; i += batchSize) {
					const batch = invalidKeys.slice(i, i + batchSize);
					const placeholders = batch.map(() => '?').join(',');
					const statement = `DELETE FROM api_keys WHERE api_key IN (${placeholders})`;
					await this.ctx.storage.sql.exec(statement, ...batch);
				}
				console.log(`移除了 ${invalidKeys.length} 个无效的API密钥。`);
			}

			return new Response(JSON.stringify(checkResults), {
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('检查API密钥失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	// async getAllApiKeys(): Promise<Response> {
	// 	try {
	// 		const results = await this.ctx.storage.sql.exec('SELECT * FROM api_keys').raw();
	// 		const keys = Array.from(results);
	// 		console.log('getAllApiKeys keys: ', keys);
	// 		return new Response(JSON.stringify({ keys }), {
	// 			headers: { 'Content-Type': 'application/json' },
	// 		});
			
	// 	} catch (error: any) {
	// 		console.error('获取API密钥失败:', error);
	// 		return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
	// 			status: 500,
	// 			headers: { 'Content-Type': 'application/json' },
	// 		});
	// 	}
	// }

	// ... existing code ...
async getAllApiKeys(): Promise<Response> {
	try {
		const results = await this.ctx.storage.sql.exec('SELECT * FROM api_keys').raw();
		const rawKeys = Array.from(results);
		console.log('getAllApiKeys keys: ', rawKeys);
		
		// 将原始数组转换为对象数组
		const keys = rawKeys.map(([api_key, total_calls]) => ({
			api_key,
			total_calls: total_calls || 0
		}));
		
		return new Response(JSON.stringify({ keys }), {
			headers: { 'Content-Type': 'application/json' },
		});
		
	} catch (error: any) {
		console.error('获取API密钥失败:', error);
		return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}
// ... existing code ...

	async handleApiKeysStats(): Promise<Response> {
		try {
			const now = Math.floor(Date.now() / 1000);
			const oneMinuteAgo = now - 60;
			const twentyFourHoursAgo = now - 24 * 60 * 60;

			// Clean up old logs first
			await this.ctx.storage.sql.exec('DELETE FROM api_key_usage_logs WHERE timestamp < ?', twentyFourHoursAgo - 60); // A little buffer

			const keysResult = await this.ctx.storage.sql.exec('SELECT api_key, total_calls FROM api_keys').raw<any>();
			const keys = Array.from(keysResult);

			const stats = await Promise.all(
				keys.map(async (key) => {
					const [api_key, total_calls] = key as [string, number];

					const oneMinuteCountResult = await this.ctx.storage.sql
						.exec('SELECT COUNT(*) as count FROM api_key_usage_logs WHERE api_key = ? AND timestamp >= ?', api_key, oneMinuteAgo)
						.raw<any>();
					const oneMinuteCount = (Array.from(oneMinuteCountResult)[0]?.[0] as number) ?? 0

					const twentyFourHourCountResult = await this.ctx.storage.sql
						.exec(
							'SELECT COUNT(*) as count FROM api_key_usage_logs WHERE api_key = ? AND timestamp >= ?',
							api_key,
							twentyFourHoursAgo
						)
						.raw<any>();
					const twentyFourHourCount = (Array.from(twentyFourHourCountResult)[0]?.[0] as number) ?? 0;

					return {
						api_key,
						total_calls,
						one_minute_calls: oneMinuteCount,
						twenty_four_hour_calls: twentyFourHourCount,
					};
				})
			);

			return new Response(JSON.stringify(stats), {
				headers: { 'Content-Type': 'application/json' },
			});
		} catch (error: any) {
			console.error('获取API密钥统计失败:', error);
			return new Response(JSON.stringify({ error: error.message || '内部服务器错误' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json' },
			});
		}
	}

	// =================================================================================================
	// Helper Methods
	// =================================================================================================

	private async getRandomApiKey(): Promise<string | null> {
		try {
			const results = await this.ctx.storage.sql.exec('SELECT api_key FROM api_keys ORDER BY RANDOM() LIMIT 1').raw<any>();
			const keys = Array.from(results);
			if (keys && keys.length > 0) {
				const key = keys[0] as any;
				console.log(`Gemini Selected API Key (Fallback): ${key.api_key}`);
				return key.api_key;
			}
			return null;
		} catch (error) {
			console.error('获取随机API密钥失败:', error);
			return null;
		}
	}

	private async getNextApiKeyInRotation(): Promise<string | null> {
		try {
			// Use blockConcurrencyWhile to ensure atomicity of the counter operations during concurrent requests
			return await this.ctx.blockConcurrencyWhile(async () => {
				const allKeysResult = await this.ctx.storage.sql.exec('SELECT api_key FROM api_keys').raw();
				if (!allKeysResult) {
					return null;
				}
				const keys = Array.from(allKeysResult).map((row) => String(row[0]));

				if (!keys || keys.length === 0) {
					return null;
				}

				let currentIndex = (await this.ctx.storage.get<number>('round_robin_index')) ?? 0;

				if (currentIndex >= keys.length) {
					currentIndex = 0;
				}

				const selectedKey = keys[currentIndex];
				const nextIndex = (currentIndex + 1) % keys.length;
				await this.ctx.storage.put('round_robin_index', nextIndex);

				// Log the usage
				const timestamp = Math.floor(Date.now() / 1000);
				await this.ctx.storage.sql.exec('UPDATE api_keys SET total_calls = total_calls + 1 WHERE api_key = ?', selectedKey);
				await this.ctx.storage.sql.exec('INSERT INTO api_key_usage_logs (api_key, timestamp) VALUES (?, ?)', selectedKey, timestamp);

				console.log(`Gemini Selected API Key (Round-Robin): ${selectedKey}`);
				return selectedKey;
			});
		} catch (error) {
			console.error('轮询获取API密钥失败:', error);
			// Fallback to random selection in case of an error to maintain system robustness
			return this.getRandomApiKey();
		}
	}

	private async handleOpenAI(request: Request): Promise<Response> {
		const authKey = this.env.AUTH_KEY;
		let apiKey: string | null;

		const authHeader = request.headers.get('Authorization');
		apiKey = authHeader?.replace('Bearer ', '') ?? null;
		if (!apiKey) {
			return new Response('No API key found in the client headers,please check your request!', { status: 400 });
		}

		if (authKey && !this.env.FORWARD_CLIENT_KEY_ENABLED) {
			const authHeader = request.headers.get('Authorization');
			const token = authHeader?.replace('Bearer ', '');
			if (token !== authKey) {
				return new Response('Unauthorized', { status: 401, headers: fixCors({}).headers });
			}
			apiKey = await this.getNextApiKeyInRotation();
			if (!apiKey) {
				return new Response('No API keys configured in the load balancer.', { status: 500 });
			}
		}

		const url = new URL(request.url);
		const pathname = url.pathname;

		const assert = (success: Boolean) => {
			if (!success) {
				throw new HttpError('The specified HTTP method is not allowed for the requested resource', 400);
			}
		};
		const errHandler = (err: Error) => {
			console.error(err);
			return new Response(err.message, fixCors({ statusText: err.message ?? 'Internal Server Error', status: 500 }));
		};

		switch (true) {
			case pathname.endsWith('/chat/completions'):
				assert(request.method === 'POST');
				return this.handleCompletions(await request.json(), apiKey).catch(errHandler);
			case pathname.endsWith('/embeddings'):
				assert(request.method === 'POST');
				return this.handleEmbeddings(await request.json(), apiKey).catch(errHandler);
			case pathname.endsWith('/models'):
				assert(request.method === 'GET');
				return this.handleModels(apiKey).catch(errHandler);
			default:
				throw new HttpError('404 Not Found', 404);
		}
	}
}
