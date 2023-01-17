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

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

class LRUCacheTest {

	@Test
	void keepCacheSize() {
		LRUCache<String, String> cache = new LRUCache<>(3);

		cache.put("1", "first");
		cache.put("2", "second");
		cache.put("3", "third");

		assertMap(cache, "1", "2", "3");

		cache.put("4", "fourth");
		assertMap(cache, "2", "3", "4");
		
		cache.put("5", "fifth");
		assertMap(cache, "3", "4", "5");
	}


	@Test
	void evictLeastUsed() {
		LRUCache<String, String> cache = new LRUCache<>(3);

		cache.put("1", "first");
		cache.put("2", "second");
		cache.put("3", "third");
		assertMap(cache, "1", "2", "3");

		cache.get("1");
		cache.get("3");
				
		cache.put("4", "fourth");

		assertMap(cache, "1", "3", "4");
		
		assertFalse(cache.get("2").isPresent());
		
	}

	
	private void assertMap(LRUCache<String, String> cache, String... content) {
		Arrays.stream(content).forEach(entry -> assertTrue(cache.get(entry).isPresent(), "Wert "+entry+ " nicht im Cache gefunden"));
	}

}
