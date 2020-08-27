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

import java.util.concurrent.Callable;

/**
 * Eine funktionale Schnittstelle, die ein beliebiges Ergebnis produzieren kann und dabei möglicherweise eine
 * {@link KksException} auslöst.
 *
 * @param <V> Der Typ des Erzeugnisses.
 */
@FunctionalInterface
public interface KksCallable<V> extends Callable<V> {

    @Override
    V call() throws KksException;
}
