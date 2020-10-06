/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of secon-tool
 * (see https://github.com/DieTechniker/secon-tool).
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
package de.tk.opensource.secon;

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
        final SearchControls cons = searchControls(scope, attrs);
        final List<T> result = new LinkedList<>();
        NamingCollection
                .from(() -> context().search(base, filter, cons))
                .forEach(searchResult -> NamingCollection
                        .from(searchResult.getAttributes()::getAll)
                        .forEach(attr -> NamingCollection
                                .from(attr::getAll)
                                .forEach(value -> result.add((T) value))));
        return result;
    }

    default SearchControls searchControls(final int scope, final String... attrs) {
        final SearchControls cons = new SearchControls();
        cons.setSearchScope(scope);
        cons.setReturningAttributes(attrs);
        return cons;
    }
}
