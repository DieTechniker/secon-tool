/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.tk.security.kks;

import global.namespace.fun.io.api.function.XConsumer;

import javax.naming.NamingEnumeration;
import java.util.concurrent.Callable;

/**
 * @author Christian Schlichtherle
 */
@FunctionalInterface
interface NamingCollection<T> {

    static <T> NamingCollection<T> from(Callable<NamingEnumeration<T>> c) {
        return c::call;
    }

    NamingEnumeration<T> newEnumeration() throws Exception;

    default void forEach(final XConsumer<T> consumer) throws Exception {
        final NamingEnumeration<T> e = newEnumeration();
        SideEffect.runAll(
                () -> {
                    while (e.hasMore()) {
                        consumer.accept(e.next());
                    }
                },
                e::close);
    }
}
