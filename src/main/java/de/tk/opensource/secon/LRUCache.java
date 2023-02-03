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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Einfacher least-recently-used (LRU) Cache auf Basis einer synchronized {@link LinkedHashMap}.
 * 
 * @author Wolfgang Schmiesing
 */
class LRUCache<K,V> {

    private final Map<K, V> internalMap;

	public LRUCache(int capacity) {
       internalMap = Collections.synchronizedMap(new LinkedHashMap<K, V>(capacity, 0.75F, true) {
    	   
		private static final long serialVersionUID = 1L;

		@Override
         protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return size() > capacity;
         }
      });
    }

    public void put(K key, V value) {
       internalMap.put(key, value);
    }

    public Optional<V> get(K key) {
      return Optional.ofNullable(internalMap.get(key));
    }

	public boolean containsKey(K key) {
		return get(key).isPresent();
	}

	@Override
	public String toString() {
		return "LRUCache [" + internalMap + "]";
	}
} 

