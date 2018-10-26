/*
 * Copyright © 2018 Lisk Foundation
 *
 * See the LICENSE file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with the Lisk Foundation,
 * no part of this software, including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE file.
 *
 * Removal or modification of this copyright notice is prohibited.
 *
 */
import { AxiosRequestConfig } from 'axios';
import { GET } from './constants';
import {
	ApiHandler,
	ApiResponse,
	HashMap,
	RequestConfig,
	Resource,
} from './types/lisk-api-client';
import { solveURLParams, toQueryString } from './utils';

// Bind to resource class
export const apiMethod = (options: RequestConfig = {}): ApiHandler =>
	async function apiHandler(
		this: Resource,
		// tslint:disable-next-line readonly-array
		...args: Array<number | string | object>
	): Promise<ApiResponse | Error> {
		const {
			method = GET,
			path = '',
			urlParams = [],
			validator,
			defaultData = {},
			retry = false,
		} = options;

		if (urlParams.length > 0 && args.length < urlParams.length) {
			return Promise.reject(
				new Error(
					`This endpoint must be supplied with the following parameters: ${urlParams.toString()}`,
				),
			);
		}

		const data = {
			...defaultData,
			...(args.length > urlParams.length &&
			typeof args[urlParams.length] === 'object'
				? (args[urlParams.length] as object)
				: {}),
		};

		if (validator) {
			try {
				validator(data);
			} catch (err) {
				return Promise.reject(err);
			}
		}

		const resolvedURLObject = urlParams.reduce(
			(accumulator: HashMap = {}, param: string, i: number): HashMap => ({
				...accumulator,
				[param]: args[i] as string,
			}),
			{},
		);

		const requestData: AxiosRequestConfig = {
			headers: this.headers,
			method,
			url: solveURLParams(
				`${this.resourcePath}${path}`,
				resolvedURLObject as HashMap,
			),
		};

		if (Object.keys(data).length > 0) {
			if (method === GET) {
				requestData.url += `?${toQueryString(data)}`;
			} else {
				requestData.data = data;
			}
		}

		return this.request(requestData, retry);
	};
