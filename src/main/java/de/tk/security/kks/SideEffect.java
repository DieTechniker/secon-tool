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

/**
 * @author Christian Schlichtherle
 */
@FunctionalInterface
interface SideEffect<X extends Exception> {

    @SafeVarargs
    static <X extends Exception> void runAll(final SideEffect<X> first, final SideEffect<X>... others) throws X {
        SideEffect<X> acc = first;
        for (SideEffect<X> other : others) {
            acc = acc.andThen(other);
        }
        acc.run();
    }

    void run() throws X;

    default <Y extends X> SideEffect<X> andThen(final SideEffect<Y> that) {
        return () -> {
            Throwable t1 = null;
            try {
                this.run();
            } catch (final Throwable t) {
                t1 = t;
                throw t;
            } finally {
                try {
                    that.run();
                } catch (final Throwable t) {
                    if (null == t1) {
                        throw t;
                    } else {
                        t1.addSuppressed(t);
                    }
                }
            }
        };
    }
}
