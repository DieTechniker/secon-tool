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

import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Christian Schlichtherle
 */
@FunctionalInterface
interface DirContextVisitor {

    DirContext context();

    @SuppressWarnings("unchecked")
    default <T> List<T> search(final String base, final String filter, final int scope, final String... attrs) throws Exception {
        final List<T> result = new LinkedList<>();
        NamingCollection
                .from(() -> context().search(base, filter, newSearchControls(scope, attrs)))
                .forEach(searchResult -> NamingCollection
                        .from(searchResult.getAttributes()::getAll)
                        .forEach(attr -> NamingCollection
                                .from(attr::getAll)
                                .forEach(value -> result.add((T) value))));
        return result;
    }

    default SearchControls newSearchControls(final int scope, final String... attrs) {
        final SearchControls cons = new SearchControls();
        cons.setSearchScope(scope);
        cons.setReturningAttributes(attrs);
        return cons;
    }
}
