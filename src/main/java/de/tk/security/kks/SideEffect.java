/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of kks-encryption
 * (see https://github.com/DieTechniker/kks-encryption).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
