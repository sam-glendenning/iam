/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
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
package it.infn.mw.iam.api.common.client;

import static java.util.Collections.emptySet;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

public class StringAsSetOfStringsDeserializer extends JsonDeserializer<Set<String>> {

  @Override
  public Set<String> deserialize(JsonParser p, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {

    String stringValue = p.getValueAsString();

    if (stringValue == null) {
      return emptySet();
    }

    return Arrays.stream(stringValue.trim().split(" "))
      .map(String::trim)
      .collect(Collectors.toSet());

  }

}