/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * RevetSec helpers for applications on the {@code jakarta.servlet} API.
 * <p>
 * The helpers are static classes. They pass an {@code HttpServletRequest} to RevetSec core as raw input (query
 * string, form body or parameters, header values) and write RevetSec results to an {@code HttpServletResponse}.
 * They contain no protocol logic: every validation decision is made by RevetSec core, through its public API only.
 * <p>
 * RevetSec core and the Servlet API are {@code provided} dependencies of this adapter: an application declares
 * core, and its servlet container supplies the Servlet API. The {@code revetsec-servlet-javax} adapter has the same
 * helpers for the legacy {@code javax.servlet} API.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.servlet.jakarta;

import org.jspecify.annotations.NullMarked;
