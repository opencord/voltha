/*
 * Copyright 2017-present Open Networking Foundation

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"github.com/opencord/voltha/netconf/translator/voltha"
	"reflect"
	"fmt"
)

var StructMap map[string]map[string]string

func init() {
	StructMap = make(map[string]map[string]string)
}

func addArrayType(newType string) {
	if _, ok := StructMap[newType+"Array"]; !ok {
		StructMap[newType+"Array"] = make(map[string]string)
		StructMap[newType+"Array"]["items"] = newType + "*"
		StructMap[newType+"Array"]["size"] = "int"
	}

}

func addEnumType(newType string) {
	if _, ok := StructMap[newType]; !ok {
		StructMap[newType] = make(map[string]string)
		StructMap[newType]["Type"] = "enum " + newType + "Enum"
		StructMap[newType]["Value"] = "char*"
	}
}

func traverseVolthaStructures(original reflect.Value) string {
	field_type := ""

	switch original.Kind() {

	case reflect.Ptr:
		field_type = traverseVolthaStructures(original.Elem())

	case reflect.Interface:
		addEnumType(original.Type().Name())
		field_type = original.Type().Name()

	case reflect.Struct:
		for i := 0; i < original.NumField(); i += 1 {
			field_type = ""
			if original.Field(i).Kind() == reflect.Ptr {
				newType := reflect.New(original.Type().Field(i).Type.Elem())
				traverseVolthaStructures(reflect.Indirect(newType))
				field_type = original.Type().Field(i).Type.Elem().Name() + "*"
			} else {
				field_type = traverseVolthaStructures(original.Field(i))
			}
			if _, ok := StructMap[original.Type().Name()]; !ok {
				StructMap[original.Type().Name()] = make(map[string]string)
			}
			if _, ok := StructMap[original.Type().Name()][original.Type().Field(i).Name]; !ok {
				if field_type == "" {
					StructMap[original.Type().Name()][original.Type().Field(i).Name] =
						string(original.Type().Field(i).Type.String())
				} else {
					StructMap[original.Type().Name()][original.Type().Field(i).Name] =
						field_type
				}
			}
		}

	case reflect.Slice:
		if original.Type().Elem().Kind() == reflect.Ptr {
			newType := reflect.New(original.Type().Elem().Elem())
			field_type = newType.Type().Elem().Name() + "Array"
			traverseVolthaStructures(reflect.Indirect(newType))
			addArrayType(newType.Type().Elem().Name())
		} else {
			field_type = original.Type().Elem().Kind().String() + "Array"
			addArrayType(original.Type().Elem().Kind().String())
		}

	//case reflect.Map:
	//	for _, key := range original.MapKeys() {
	//		originalValue := original.MapIndex(key)
	//	}

	case reflect.String:
		field_type = "string"
		break

	default:
		field_type = original.Kind().String()
	}

	return field_type
}

func main() {
	traverseVolthaStructures(reflect.ValueOf(voltha.Voltha{}))

	fmt.Printf("#ifndef VOLTHA_DEFS\n")
	fmt.Printf("#define VOLTHA_DEFS\n")
	fmt.Printf("\n#include <stdint.h>\n")
	var attribute_type string
	for k, v := range StructMap {
		fmt.Printf("\ntypedef struct {\n")
		for kk, vv := range v {
			attribute_type = vv
			switch vv {
			case "string*":
				attribute_type = "char**"
			case "string":
				attribute_type = "char*"
			case "int32":
				attribute_type = "int32_t"
			case "uint8*":
				fallthrough
			case "uint8":
				attribute_type = "uint8_t"
			case "uint32*":
				fallthrough
			case "uint32":
				attribute_type = "uint32_t"
			case "uint64*":
				fallthrough
			case "uint64":
				attribute_type = "uint64_t"
			case "bool":
				attribute_type = "int"
			}
			fmt.Printf("\t%s %s;\n", attribute_type, kk)
		}
		fmt.Printf("} %s;\n", k)
	}
	fmt.Printf("\n#endif\n")
}
