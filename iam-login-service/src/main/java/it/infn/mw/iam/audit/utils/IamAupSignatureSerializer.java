/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2018
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
package it.infn.mw.iam.audit.utils;

import java.io.IOException;

import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import it.infn.mw.iam.persistence.model.IamAupSignature;

public class IamAupSignatureSerializer extends JsonSerializer<IamAupSignature> {

  private final DateTimeFormatter dateTimeFormatter = ISODateTimeFormat.dateTime();

  @Override
  public void serialize(IamAupSignature value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException {

    gen.writeStartObject();
    gen.writeNumberField("aupId", value.getAup().getId());
    gen.writeStringField("username", value.getAccount().getUsername());
    gen.writeStringField("signatureTime",
        dateTimeFormatter.print(value.getSignatureTime().getTime()));
    gen.writeEndObject();
  }
  
}