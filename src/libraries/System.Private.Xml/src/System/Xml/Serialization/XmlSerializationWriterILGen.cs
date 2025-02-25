// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Xml.Schema;

namespace System.Xml.Serialization
{
    [RequiresUnreferencedCode(XmlSerializer.TrimSerializationWarning)]
    [RequiresDynamicCode(XmlSerializer.AotSerializationWarning)]
    internal sealed class XmlSerializationWriterILGen : XmlSerializationILGen
    {
        internal XmlSerializationWriterILGen(TypeScope[] scopes, string access, string className)
            : base(scopes, access, className)
        {
        }

        internal void GenerateBegin()
        {
            this.typeBuilder = CodeGenerator.CreateTypeBuilder(
                ModuleBuilder,
                ClassName,
                TypeAttributes | TypeAttributes.BeforeFieldInit,
                typeof(XmlSerializationWriter),
                Type.EmptyTypes);

            foreach (TypeScope scope in Scopes)
            {
                foreach (TypeMapping mapping in scope.TypeMappings)
                {
                    if (mapping is StructMapping || mapping is EnumMapping)
                    {
                        MethodNames.Add(mapping, NextMethodName(mapping.TypeDesc!.Name));
                    }
                }
                ReflectionAwareILGen.WriteReflectionInit(scope);
            }
        }

        internal override void GenerateMethod(TypeMapping mapping)
        {
            if (!GeneratedMethods.Add(mapping))
                return;

            if (mapping is StructMapping)
            {
                WriteStructMethod((StructMapping)mapping);
            }
            else if (mapping is EnumMapping)
            {
                WriteEnumMethod((EnumMapping)mapping);
            }
        }

        internal Type GenerateEnd()
        {
            GenerateReferencedMethods();
            GenerateInitCallbacksMethod();
            this.typeBuilder.DefineDefaultConstructor(
                CodeGenerator.PublicMethodAttributes);
            return this.typeBuilder.CreateType();
        }

        internal string? GenerateElement(XmlMapping xmlMapping)
        {
            if (!xmlMapping.IsWriteable)
                return null;
            if (!xmlMapping.GenerateSerializer)
                throw new ArgumentException(SR.XmlInternalError, nameof(xmlMapping));
            if (xmlMapping is XmlTypeMapping)
                return GenerateTypeElement((XmlTypeMapping)xmlMapping);
            else if (xmlMapping is XmlMembersMapping)
                return GenerateMembersElement((XmlMembersMapping)xmlMapping);
            else
                throw new ArgumentException(SR.XmlInternalError, nameof(xmlMapping));
        }

        private void GenerateInitCallbacksMethod()
        {
            ilg = new CodeGenerator(this.typeBuilder);
            ilg.BeginMethod(typeof(void), "InitCallbacks", Type.EmptyTypes, Array.Empty<string>(),
                CodeGenerator.ProtectedOverrideMethodAttributes);
            ilg.EndMethod();
        }

        private void WriteQualifiedNameElement(string name, string? ns, object? defaultValue, SourceInfo source, bool nullable, TypeMapping mapping)
        {
            bool hasDefault = defaultValue != null && defaultValue != DBNull.Value;
            if (hasDefault)
            {
                throw Globals.NotSupported("XmlQualifiedName DefaultValue not supported.  Fail in WriteValue()");
            }
            List<Type> argTypes = new List<Type>();
            ilg.Ldarg(0);
            ilg.Ldstr(GetCSharpString(name));
            argTypes.Add(typeof(string));
            if (ns != null)
            {
                ilg.Ldstr(GetCSharpString(ns));
                argTypes.Add(typeof(string));
            }
            source.Load(mapping.TypeDesc!.Type!);
            argTypes.Add(mapping.TypeDesc.Type!);

            MethodInfo XmlSerializationWriter_WriteXXX = typeof(XmlSerializationWriter).GetMethod(
                 nullable ? ("WriteNullableQualifiedNameLiteral") : "WriteElementQualifiedName",
                 CodeGenerator.InstanceBindingFlags,
                 argTypes.ToArray()
                 )!;
            ilg.Call(XmlSerializationWriter_WriteXXX);
        }

        private void WriteEnumValue(EnumMapping mapping, SourceInfo source, out Type returnType)
        {
            string? methodName = ReferenceMapping(mapping);

#if DEBUG
            // use exception in the place of Debug.Assert to avoid throwing asserts from a server process such as aspnet_ewp.exe
            if (methodName == null) throw new InvalidOperationException(SR.Format(SR.XmlInternalErrorMethod, mapping.TypeDesc!.Name));
#endif

            // For enum, its write method (eg. Write1_Gender) could be called multiple times
            // prior to its declaration.
            MethodBuilder methodBuilder = EnsureMethodBuilder(typeBuilder,
                    methodName!,
                    CodeGenerator.PrivateMethodAttributes,
                    typeof(string),
                    new Type[] { mapping.TypeDesc!.Type! });
            ilg.Ldarg(0);
            source.Load(mapping.TypeDesc.Type!);
            ilg.Call(methodBuilder);
            returnType = typeof(string);
        }

        private void WritePrimitiveValue(TypeDesc typeDesc, SourceInfo source, out Type returnType)
        {
            if (typeDesc == StringTypeDesc || typeDesc.FormatterName == "String")
            {
                source.Load(typeDesc.Type!);
                returnType = typeDesc.Type!;
            }
            else
            {
                if (!typeDesc.HasCustomFormatter)
                {
                    Type argType = typeDesc.Type!;
                    // No ToString(Byte), compiler used ToString(Int16) instead.
                    if (argType == typeof(byte))
                        argType = typeof(short);
                    // No ToString(UInt16), compiler used ToString(Int32) instead.
                    else if (argType == typeof(ushort))
                        argType = typeof(int);
                    MethodInfo XmlConvert_ToString = typeof(XmlConvert).GetMethod(
                        "ToString",
                        CodeGenerator.StaticBindingFlags,
                        new Type[] { argType }
                        )!;
                    source.Load(typeDesc.Type!);
                    ilg.Call(XmlConvert_ToString);
                    returnType = XmlConvert_ToString.ReturnType;
                }
                else
                {
                    // Only these methods below that is non Static and need to ldarg("this") for Call.
                    BindingFlags bindingFlags = CodeGenerator.StaticBindingFlags;
                    if (typeDesc.FormatterName == "XmlQualifiedName")
                    {
                        bindingFlags = CodeGenerator.InstanceBindingFlags;
                        ilg.Ldarg(0);
                    }
                    MethodInfo FromXXX = typeof(XmlSerializationWriter).GetMethod(
                        $"From{typeDesc.FormatterName}",
                           bindingFlags,
                           new Type[] { typeDesc.Type! }
                           )!;
                    source.Load(typeDesc.Type!);
                    ilg.Call(FromXXX);
                    returnType = FromXXX.ReturnType;
                }
            }
        }

        private void WritePrimitive(string method, string name, string? ns, object? defaultValue, SourceInfo source, TypeMapping mapping, bool writeXsiType, bool isElement, bool isNullable)
        {
            TypeDesc typeDesc = mapping.TypeDesc!;
            bool hasDefault = defaultValue != null && defaultValue != DBNull.Value && mapping.TypeDesc!.HasDefaultSupport;
            if (hasDefault)
            {
                if (mapping is EnumMapping)
                {
#if DEBUG
                    // use exception in the place of Debug.Assert to avoid throwing asserts from a server process such as aspnet_ewp.exe
                    if (defaultValue!.GetType() != typeof(string)) throw new InvalidOperationException(SR.Format(SR.XmlInternalErrorDetails, name + " has invalid default type " + defaultValue.GetType().Name));
#endif

                    source.Load(mapping.TypeDesc!.Type!);
                    string? enumDefaultValue = null;
                    if (((EnumMapping)mapping).IsFlags)
                    {
                        string[] values = ((string)defaultValue!).Split(null);
                        for (int i = 0; i < values.Length; i++)
                        {
                            if (string.IsNullOrEmpty(values[i]))
                                continue;
                            if (i > 0)
                                enumDefaultValue += ", ";
                            enumDefaultValue += values[i];
                        }
                    }
                    else
                    {
                        enumDefaultValue = (string)defaultValue!;
                    }
                    ilg.Ldc(Enum.Parse(mapping.TypeDesc.Type!, enumDefaultValue!, false));
                    ilg.If(Cmp.NotEqualTo); // " != "
                }
                else
                {
                    WriteCheckDefault(source, defaultValue!, isNullable);
                }
            }
            List<Type> argTypes = new List<Type>();
            ilg.Ldarg(0);
            argTypes.Add(typeof(string));
            ilg.Ldstr(GetCSharpString(name));
            if (ns != null)
            {
                argTypes.Add(typeof(string));
                ilg.Ldstr(GetCSharpString(ns));
            }
            Type argType;

            if (mapping is EnumMapping)
            {
                WriteEnumValue((EnumMapping)mapping, source, out argType);
                argTypes.Add(argType);
            }
            else
            {
                WritePrimitiveValue(typeDesc, source, out argType);
                argTypes.Add(argType);
            }

            if (writeXsiType)
            {
                argTypes.Add(typeof(XmlQualifiedName));
                ConstructorInfo XmlQualifiedName_ctor = typeof(XmlQualifiedName).GetConstructor(
                    CodeGenerator.InstanceBindingFlags,
                    new Type[] { typeof(string), typeof(string) }
                    )!;
                ilg.Ldstr(GetCSharpString(mapping.TypeName));
                ilg.Ldstr(GetCSharpString(mapping.Namespace));
                ilg.New(XmlQualifiedName_ctor);
            }

            MethodInfo XmlSerializationWriter_method = typeof(XmlSerializationWriter).GetMethod(
                   method,
                   CodeGenerator.InstanceBindingFlags,
                   argTypes.ToArray()
                   )!;
            ilg.Call(XmlSerializationWriter_method);

            if (hasDefault)
            {
                ilg.EndIf();
            }
        }

        private void WriteTag(string methodName, string name, string? ns)
        {
            MethodInfo XmlSerializationWriter_Method = typeof(XmlSerializationWriter).GetMethod(
                methodName,
                CodeGenerator.InstanceBindingFlags,
                new Type[] { typeof(string), typeof(string) }
                )!;
            ilg.Ldarg(0);
            ilg.Ldstr(GetCSharpString(name));
            ilg.Ldstr(GetCSharpString(ns));
            ilg.Call(XmlSerializationWriter_Method);
        }

        private void WriteTag(string methodName, string name, string? ns, bool writePrefixed)
        {
            MethodInfo XmlSerializationWriter_Method = typeof(XmlSerializationWriter).GetMethod(
                methodName,
                CodeGenerator.InstanceBindingFlags,
                new Type[] { typeof(string), typeof(string), typeof(object), typeof(bool) }
                )!;
            ilg.Ldarg(0);
            ilg.Ldstr(GetCSharpString(name));
            ilg.Ldstr(GetCSharpString(ns));
            ilg.Load(null);
            ilg.Ldc(writePrefixed);
            ilg.Call(XmlSerializationWriter_Method);
        }

        private void WriteStartElement(string name, string? ns, bool writePrefixed)
        {
            WriteTag("WriteStartElement", name, ns, writePrefixed);
        }

        private void WriteEndElement()
        {
            MethodInfo XmlSerializationWriter_WriteEndElement = typeof(XmlSerializationWriter).GetMethod(
                "WriteEndElement",
                CodeGenerator.InstanceBindingFlags,
                Type.EmptyTypes
                )!;
            ilg.Ldarg(0);
            ilg.Call(XmlSerializationWriter_WriteEndElement);
        }
        private void WriteEndElement(string source)
        {
            MethodInfo XmlSerializationWriter_WriteEndElement = typeof(XmlSerializationWriter).GetMethod(
                "WriteEndElement",
                CodeGenerator.InstanceBindingFlags,
                s_objectType
                )!;
            object oVar = ilg.GetVariable(source);
            ilg.Ldarg(0);
            ilg.Load(oVar);
            ilg.ConvertValue(CodeGenerator.GetVariableType(oVar), typeof(object));
            ilg.Call(XmlSerializationWriter_WriteEndElement);
        }

        private void WriteLiteralNullTag(string name, string? ns)
        {
            WriteTag("WriteNullTagLiteral", name, ns);
        }

        private void WriteEmptyTag(string name, string? ns)
        {
            WriteTag("WriteEmptyTag", name, ns);
        }

        private static readonly string[] s_argNamesP = new string[] { "p" };
        private static readonly string[] s_argNamesO = new string[] { "o" };
        private static readonly Type[] s_objectArrayType = new Type[] { typeof(object[]) };
        private static readonly Type[] s_objectType = new Type[] { typeof(object) };

        private string GenerateMembersElement(XmlMembersMapping xmlMembersMapping)
        {
            ElementAccessor element = xmlMembersMapping.Accessor;
            MembersMapping mapping = (MembersMapping)element.Mapping!;
            bool hasWrapperElement = mapping.HasWrapperElement;
            bool writeAccessors = mapping.WriteAccessors;
            string methodName = NextMethodName(element.Name);
            ilg = new CodeGenerator(this.typeBuilder);
            ilg.BeginMethod(
                typeof(void),
                methodName,
                s_objectArrayType,
                s_argNamesP,
                CodeGenerator.PublicMethodAttributes
                );

            MethodInfo XmlSerializationWriter_WriteStartDocument = typeof(XmlSerializationWriter).GetMethod(
                "WriteStartDocument",
                CodeGenerator.InstanceBindingFlags,
                Type.EmptyTypes
                )!;
            ilg.Ldarg(0);
            ilg.Call(XmlSerializationWriter_WriteStartDocument);

            MethodInfo XmlSerializationWriter_TopLevelElement = typeof(XmlSerializationWriter).GetMethod(
                "TopLevelElement",
                CodeGenerator.InstanceBindingFlags,
                Type.EmptyTypes
                )!;
            ilg.Ldarg(0);
            ilg.Call(XmlSerializationWriter_TopLevelElement);

            // in the top-level method add check for the parameters length,
            // because visual basic does not have a concept of an <out> parameter it uses <ByRef> instead
            // so sometime we think that we have more parameters then supplied
            LocalBuilder pLengthLoc = ilg.DeclareLocal(typeof(int), "pLength");
            ilg.Ldarg("p");
            ilg.Ldlen();
            ilg.Stloc(pLengthLoc);

            if (hasWrapperElement)
            {
                WriteStartElement(element.Name, (element.Form == XmlSchemaForm.Qualified ? element.Namespace : ""), false);

                int xmlnsMember = FindXmlnsIndex(mapping.Members!);
                if (xmlnsMember >= 0)
                {
                    string source = string.Create(CultureInfo.InvariantCulture, $"(({typeof(XmlSerializerNamespaces).FullName})p[{xmlnsMember}])");

                    ilg.Ldloc(pLengthLoc);
                    ilg.Ldc(xmlnsMember);
                    ilg.If(Cmp.GreaterThan);
                    WriteNamespaces(source);
                    ilg.EndIf();
                }

                for (int i = 0; i < mapping.Members!.Length; i++)
                {
                    MemberMapping member = mapping.Members[i];

                    if (member.Attribute != null && !member.Ignore)
                    {
                        SourceInfo source = new SourceInfo($"p[{i}]", null, null, pLengthLoc.LocalType.GetElementType()!, ilg);

                        SourceInfo? specifiedSource = null;
                        int specifiedPosition = 0;
                        if (member.CheckSpecified != SpecifiedAccessor.None)
                        {
                            string memberNameSpecified = $"{member.Name}Specified";
                            for (int j = 0; j < mapping.Members.Length; j++)
                            {
                                if (mapping.Members[j].Name == memberNameSpecified)
                                {
                                    specifiedSource = new SourceInfo($"((bool)p[{j}])", null, null, typeof(bool), ilg);
                                    specifiedPosition = j;
                                    break;
                                }
                            }
                        }

                        ilg.Ldloc(pLengthLoc);
                        ilg.Ldc(i);
                        ilg.If(Cmp.GreaterThan);

                        if (specifiedSource != null)
                        {
                            Label labelTrue = ilg.DefineLabel();
                            Label labelEnd = ilg.DefineLabel();
                            ilg.Ldloc(pLengthLoc);
                            ilg.Ldc(specifiedPosition);
                            ilg.Ble(labelTrue);
                            specifiedSource.Load(typeof(bool));
                            ilg.Br_S(labelEnd);
                            ilg.MarkLabel(labelTrue);
                            ilg.Ldc(true);
                            ilg.MarkLabel(labelEnd);
                            ilg.If();
                        }

                        WriteMember(source, member.Attribute, member.TypeDesc!, "p");

                        if (specifiedSource != null)
                        {
                            ilg.EndIf();
                        }

                        ilg.EndIf();
                    }
                }
            }

            for (int i = 0; i < mapping.Members!.Length; i++)
            {
                MemberMapping member = mapping.Members[i];
                if (member.Xmlns != null)
                    continue;
                if (member.Ignore)
                    continue;

                SourceInfo? specifiedSource = null;
                int specifiedPosition = 0;
                if (member.CheckSpecified != SpecifiedAccessor.None)
                {
                    string memberNameSpecified = $"{member.Name}Specified";

                    for (int j = 0; j < mapping.Members.Length; j++)
                    {
                        if (mapping.Members[j].Name == memberNameSpecified)
                        {
                            specifiedSource = new SourceInfo($"((bool)p[{j}])", null, null, typeof(bool), ilg);
                            specifiedPosition = j;
                            break;
                        }
                    }
                }

                ilg.Ldloc(pLengthLoc);
                ilg.Ldc(i);
                ilg.If(Cmp.GreaterThan);

                if (specifiedSource != null)
                {
                    Label labelTrue = ilg.DefineLabel();
                    Label labelEnd = ilg.DefineLabel();
                    ilg.Ldloc(pLengthLoc);
                    ilg.Ldc(specifiedPosition);
                    ilg.Ble(labelTrue);
                    specifiedSource.Load(typeof(bool));
                    ilg.Br_S(labelEnd);
                    ilg.MarkLabel(labelTrue);
                    ilg.Ldc(true);
                    ilg.MarkLabel(labelEnd);
                    ilg.If();
                }

                string source = $"p[{i}]";
                string? enumSource = null;
                if (member.ChoiceIdentifier != null)
                {
                    for (int j = 0; j < mapping.Members.Length; j++)
                    {
                        if (mapping.Members[j].Name == member.ChoiceIdentifier.MemberName)
                        {
                            enumSource = $"(({mapping.Members[j].TypeDesc!.CSharpName})p[{j}])";
                            break;
                        }
                    }

#if DEBUG
                    // use exception in the place of Debug.Assert to avoid throwing asserts from a server process such as aspnet_ewp.exe
                    if (enumSource == null) throw new InvalidOperationException(SR.Format(SR.XmlInternalErrorDetails, "Can not find " + member.ChoiceIdentifier.MemberName + " in the members mapping."));
#endif
                }

                // override writeAccessors choice when we've written a wrapper element
                WriteMember(new SourceInfo(source, source, null, null, ilg), enumSource, member.ElementsSortedByDerivation!, member.Text, member.ChoiceIdentifier, member.TypeDesc!, writeAccessors || hasWrapperElement);

                if (specifiedSource != null)
                {
                    ilg.EndIf();
                }

                ilg.EndIf();
            }

            if (hasWrapperElement)
            {
                WriteEndElement();
            }
            ilg.EndMethod();
            return methodName;
        }

        private string GenerateTypeElement(XmlTypeMapping xmlTypeMapping)
        {
            ElementAccessor element = xmlTypeMapping.Accessor;
            TypeMapping mapping = element.Mapping!;
            string methodName = NextMethodName(element.Name);
            ilg = new CodeGenerator(this.typeBuilder);
            ilg.BeginMethod(
                typeof(void),
                methodName,
                s_objectType,
                s_argNamesO,
                CodeGenerator.PublicMethodAttributes
                );

            MethodInfo XmlSerializationWriter_WriteStartDocument = typeof(XmlSerializationWriter).GetMethod(
                "WriteStartDocument",
                CodeGenerator.InstanceBindingFlags,
                Type.EmptyTypes
                )!;
            ilg.Ldarg(0);
            ilg.Call(XmlSerializationWriter_WriteStartDocument);

            ilg.If(ilg.GetArg("o"), Cmp.EqualTo, null);
            if (element.IsNullable)
            {
                WriteLiteralNullTag(element.Name, (element.Form == XmlSchemaForm.Qualified ? element.Namespace : ""));
            }
            else
                WriteEmptyTag(element.Name, (element.Form == XmlSchemaForm.Qualified ? element.Namespace : ""));
            ilg.GotoMethodEnd();
            ilg.EndIf();

            if (!mapping.TypeDesc!.IsValueType && !mapping.TypeDesc.Type!.IsPrimitive)
            {
                MethodInfo XmlSerializationWriter_TopLevelElement = typeof(XmlSerializationWriter).GetMethod(
                      "TopLevelElement",
                      CodeGenerator.InstanceBindingFlags,
                      Type.EmptyTypes
                      )!;
                ilg.Ldarg(0);
                ilg.Call(XmlSerializationWriter_TopLevelElement);
            }

            WriteMember(new SourceInfo("o", "o", null, typeof(object), ilg), null, new ElementAccessor[] { element }, null, null, mapping.TypeDesc, true);

            ilg.EndMethod();
            return methodName;
        }

        private string NextMethodName(string name)
        {
            return string.Create(CultureInfo.InvariantCulture, $"Write{++NextMethodNumber}_{CodeIdentifier.MakeValidInternal(name)}");
        }

        private void WriteEnumMethod(EnumMapping mapping)
        {
            string? methodName;
            MethodNames.TryGetValue(mapping, out methodName);
            List<Type> argTypes = new List<Type>();
            List<string> argNames = new List<string>();
            argTypes.Add(mapping.TypeDesc!.Type!);
            argNames.Add("v");
            ilg = new CodeGenerator(this.typeBuilder);
            ilg.BeginMethod(
                typeof(string),
                GetMethodBuilder(methodName!),
                argTypes.ToArray(),
                argNames.ToArray(),
                CodeGenerator.PrivateMethodAttributes);
            LocalBuilder sLoc = ilg.DeclareLocal(typeof(string), "s");
            ilg.Load(null);
            ilg.Stloc(sLoc);
            ConstantMapping[] constants = mapping.Constants!;

            if (constants.Length > 0)
            {
                var values = new HashSet<long>();
                List<Label> caseLabels = new List<Label>();
                List<string> retValues = new List<string>();
                Label defaultLabel = ilg.DefineLabel();
                Label endSwitchLabel = ilg.DefineLabel();
                // This local is necessary; otherwise, it becomes if/else
                LocalBuilder localTmp = ilg.DeclareLocal(mapping.TypeDesc.Type!, "localTmp");
                ilg.Ldarg("v");
                ilg.Stloc(localTmp);
                for (int i = 0; i < constants.Length; i++)
                {
                    ConstantMapping c = constants[i];
                    if (values.Add(c.Value))
                    {
                        Label caseLabel = ilg.DefineLabel();
                        ilg.Ldloc(localTmp);
                        ilg.Ldc(Enum.ToObject(mapping.TypeDesc.Type!, c.Value));
                        ilg.Beq(caseLabel);
                        caseLabels.Add(caseLabel);
                        retValues.Add(GetCSharpString(c.XmlName));
                    }
                }


                if (mapping.IsFlags)
                {
                    ilg.Br(defaultLabel);
                    for (int i = 0; i < caseLabels.Count; i++)
                    {
                        ilg.MarkLabel(caseLabels[i]);
                        ilg.Ldc(retValues[i]);
                        ilg.Stloc(sLoc);
                        ilg.Br(endSwitchLabel);
                    }
                    ilg.MarkLabel(defaultLabel);
                    ReflectionAwareILGen.ILGenForEnumLongValue(ilg, "v");
                    LocalBuilder strArray = ilg.DeclareLocal(typeof(string[]), "strArray");
                    ilg.NewArray(typeof(string), constants.Length);
                    ilg.Stloc(strArray);
                    for (int i = 0; i < constants.Length; i++)
                    {
                        ConstantMapping c = constants[i];
                        ilg.Ldloc(strArray);
                        ilg.Ldc(i);
                        ilg.Ldstr(GetCSharpString(c.XmlName));
                        ilg.Stelem(typeof(string));
                    }
                    ilg.Ldloc(strArray);
                    LocalBuilder longArray = ilg.DeclareLocal(typeof(long[]), "longArray");
                    ilg.NewArray(typeof(long), constants.Length);
                    ilg.Stloc(longArray);

                    for (int i = 0; i < constants.Length; i++)
                    {
                        ConstantMapping c = constants[i];
                        ilg.Ldloc(longArray);
                        ilg.Ldc(i);
                        ilg.Ldc(c.Value);
                        ilg.Stelem(typeof(long));
                    }
                    ilg.Ldloc(longArray);
                    ilg.Ldstr(GetCSharpString(mapping.TypeDesc.FullName));
                    MethodInfo XmlSerializationWriter_FromEnum = typeof(XmlSerializationWriter).GetMethod(
                        "FromEnum",
                        CodeGenerator.StaticBindingFlags,
                        new Type[] { typeof(long), typeof(string[]), typeof(long[]), typeof(string) }
                        )!;
                    ilg.Call(XmlSerializationWriter_FromEnum);
                    ilg.Stloc(sLoc);
                    ilg.Br(endSwitchLabel);
                }
                else
                {
                    ilg.Br(defaultLabel);
                    // Case bodies
                    for (int i = 0; i < caseLabels.Count; i++)
                    {
                        ilg.MarkLabel(caseLabels[i]);
                        ilg.Ldc(retValues[i]);
                        ilg.Stloc(sLoc);
                        ilg.Br(endSwitchLabel);
                    }
                    MethodInfo CultureInfo_get_InvariantCulture = typeof(CultureInfo).GetMethod(
                        "get_InvariantCulture",
                        CodeGenerator.StaticBindingFlags,
                        Type.EmptyTypes
                        )!;
                    MethodInfo Int64_ToString = typeof(long).GetMethod(
                        "ToString",
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { typeof(IFormatProvider) }
                        )!;
                    MethodInfo XmlSerializationWriter_CreateInvalidEnumValueException = typeof(XmlSerializationWriter).GetMethod(
                        "CreateInvalidEnumValueException",
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { typeof(object), typeof(string) }
                        )!;
                    // Default body
                    ilg.MarkLabel(defaultLabel);
                    ilg.Ldarg(0);
                    ilg.Ldarg("v");
                    ilg.ConvertValue(mapping.TypeDesc.Type!, typeof(long));
                    LocalBuilder numLoc = ilg.DeclareLocal(typeof(long), "num");
                    ilg.Stloc(numLoc);
                    // Invoke method on Value type need address
                    ilg.LdlocAddress(numLoc);
                    ilg.Call(CultureInfo_get_InvariantCulture);
                    ilg.Call(Int64_ToString);
                    ilg.Ldstr(GetCSharpString(mapping.TypeDesc.FullName));
                    ilg.Call(XmlSerializationWriter_CreateInvalidEnumValueException);
                    ilg.Throw();
                }
                ilg.MarkLabel(endSwitchLabel);
            }
            ilg.Ldloc(sLoc);
            ilg.EndMethod();
        }

        private void WriteDerivedTypes(StructMapping mapping)
        {
            for (StructMapping? derived = mapping.DerivedMappings; derived != null; derived = derived.NextDerivedMapping)
            {
                ilg.InitElseIf();
                WriteTypeCompare("t", derived.TypeDesc!.Type!);
                ilg.AndIf();

                string? methodName = ReferenceMapping(derived);

#if DEBUG
                // use exception in the place of Debug.Assert to avoid throwing asserts from a server process such as aspnet_ewp.exe
                if (methodName == null) throw new InvalidOperationException("derived from " + mapping.TypeDesc!.FullName + ", " + SR.Format(SR.XmlInternalErrorMethod, derived.TypeDesc.Name));
#endif

                List<Type> argTypes = new List<Type>();
                ilg.Ldarg(0);
                argTypes.Add(typeof(string));
                ilg.Ldarg("n");
                argTypes.Add(typeof(string));
                ilg.Ldarg("ns");
                object oVar = ilg.GetVariable("o");
                Type oType = CodeGenerator.GetVariableType(oVar);
                ilg.Load(oVar);
                ilg.ConvertValue(oType, derived.TypeDesc.Type!);
                argTypes.Add(derived.TypeDesc.Type!);
                if (derived.TypeDesc.IsNullable)
                {
                    argTypes.Add(typeof(bool));
                    ilg.Ldarg("isNullable");
                }
                argTypes.Add(typeof(bool));
                ilg.Ldc(true);
                MethodInfo methodBuilder = EnsureMethodBuilder(typeBuilder,
                    methodName!,
                    CodeGenerator.PrivateMethodAttributes,
                    typeof(void),
                    argTypes.ToArray());
                ilg.Call(methodBuilder);
                ilg.GotoMethodEnd();

                WriteDerivedTypes(derived);
            }
        }

        private void WriteEnumAndArrayTypes()
        {
            foreach (TypeScope scope in Scopes)
            {
                foreach (Mapping m in scope.TypeMappings)
                {
                    if (m is EnumMapping)
                    {
                        EnumMapping mapping = (EnumMapping)m;
                        ilg.InitElseIf();
                        WriteTypeCompare("t", mapping.TypeDesc!.Type!);
                        // WriteXXXTypeCompare leave bool on the stack
                        ilg.AndIf();

                        string? methodName = ReferenceMapping(mapping);

#if DEBUG
                        // use exception in the place of Debug.Assert to avoid throwing asserts from a server process such as aspnet_ewp.exe
                        if (methodName == null) throw new InvalidOperationException(SR.Format(SR.XmlInternalErrorMethod, mapping.TypeDesc.Name));
#endif
                        MethodInfo XmlSerializationWriter_get_Writer = typeof(XmlSerializationWriter).GetMethod(
                            "get_Writer",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlWriter_WriteStartElement = typeof(XmlWriter).GetMethod(
                            "WriteStartElement",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string), typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Ldarg("n");
                        ilg.Ldarg("ns");
                        ilg.Call(XmlWriter_WriteStartElement);
                        MethodInfo XmlSerializationWriter_WriteXsiType = typeof(XmlSerializationWriter).GetMethod(
                            "WriteXsiType",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string), typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Ldstr(GetCSharpString(mapping.TypeName));
                        ilg.Ldstr(GetCSharpString(mapping.Namespace));
                        ilg.Call(XmlSerializationWriter_WriteXsiType);
                        MethodBuilder methodBuilder = EnsureMethodBuilder(typeBuilder,
                            methodName!,
                            CodeGenerator.PrivateMethodAttributes,
                            typeof(string),
                            new Type[] { mapping.TypeDesc.Type! }
                        );
                        MethodInfo XmlWriter_WriteString = typeof(XmlWriter).GetMethod(
                            "WriteString",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        object oVar = ilg.GetVariable("o");
                        ilg.Ldarg(0);
                        ilg.Load(oVar);
                        ilg.ConvertValue(CodeGenerator.GetVariableType(oVar), mapping.TypeDesc.Type!);
                        ilg.Call(methodBuilder);
                        ilg.Call(XmlWriter_WriteString);
                        MethodInfo XmlWriter_WriteEndElement = typeof(XmlWriter).GetMethod(
                            "WriteEndElement",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Call(XmlWriter_WriteEndElement);
                        ilg.GotoMethodEnd();
                    }
                    else if (m is ArrayMapping)
                    {
                        ArrayMapping? mapping = m as ArrayMapping;
                        if (mapping == null) continue;
                        ilg.InitElseIf();
                        if (mapping.TypeDesc!.IsArray)
                            WriteArrayTypeCompare("t", mapping.TypeDesc.Type!);
                        else
                            WriteTypeCompare("t", mapping.TypeDesc.Type!);
                        // WriteXXXTypeCompare leave bool on the stack
                        ilg.AndIf();
                        ilg.EnterScope();

                        MethodInfo XmlSerializationWriter_get_Writer = typeof(XmlSerializationWriter).GetMethod(
                            "get_Writer",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlWriter_WriteStartElement = typeof(XmlWriter).GetMethod(
                            "WriteStartElement",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string), typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Ldarg("n");
                        ilg.Ldarg("ns");
                        ilg.Call(XmlWriter_WriteStartElement);
                        MethodInfo XmlSerializationWriter_WriteXsiType = typeof(XmlSerializationWriter).GetMethod(
                            "WriteXsiType",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string), typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Ldstr(GetCSharpString(mapping.TypeName));
                        ilg.Ldstr(GetCSharpString(mapping.Namespace));
                        ilg.Call(XmlSerializationWriter_WriteXsiType);

                        WriteMember(new SourceInfo("o", "o", null, null, ilg), null, mapping.ElementsSortedByDerivation!, null, null, mapping.TypeDesc, true);

                        MethodInfo XmlWriter_WriteEndElement = typeof(XmlWriter).GetMethod(
                            "WriteEndElement",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Call(XmlWriter_WriteEndElement);
                        ilg.GotoMethodEnd();
                        ilg.ExitScope();
                    }
                }
            }
        }

        private void WriteStructMethod(StructMapping mapping)
        {
            string? methodName;
            MethodNames.TryGetValue(mapping, out methodName);

            ilg = new CodeGenerator(this.typeBuilder);
            List<Type> argTypes = new List<Type>(5);
            List<string> argNames = new List<string>(5);
            argTypes.Add(typeof(string));
            argNames.Add("n");
            argTypes.Add(typeof(string));
            argNames.Add("ns");
            argTypes.Add(mapping.TypeDesc!.Type!);
            argNames.Add("o");
            if (mapping.TypeDesc.IsNullable)
            {
                argTypes.Add(typeof(bool));
                argNames.Add("isNullable");
            }
            argTypes.Add(typeof(bool));
            argNames.Add("needType");
            ilg.BeginMethod(typeof(void),
                GetMethodBuilder(methodName!),
                argTypes.ToArray(),
                argNames.ToArray(),
                CodeGenerator.PrivateMethodAttributes);
            if (mapping.TypeDesc.IsNullable)
            {
                ilg.If(ilg.GetArg("o"), Cmp.EqualTo, null);
                {
                    ilg.If(ilg.GetArg("isNullable"), Cmp.EqualTo, true);
                    {
                        MethodInfo XmlSerializationWriter_WriteNullTagLiteral = typeof(XmlSerializationWriter).GetMethod(
                                "WriteNullTagLiteral",
                                CodeGenerator.InstanceBindingFlags,
                                new Type[] { typeof(string), typeof(string) }
                                )!;
                        ilg.Ldarg(0);
                        ilg.Ldarg("n");
                        ilg.Ldarg("ns");
                        ilg.Call(XmlSerializationWriter_WriteNullTagLiteral);
                    }
                    ilg.EndIf();
                    ilg.GotoMethodEnd();
                }
                ilg.EndIf();
            }
            ilg.If(ilg.GetArg("needType"), Cmp.NotEqualTo, true); // if (!needType)

            LocalBuilder tLoc = ilg.DeclareLocal(typeof(Type), "t");
            MethodInfo Object_GetType = typeof(object).GetMethod(
                    "GetType",
                    CodeGenerator.InstanceBindingFlags,
                    Type.EmptyTypes
                    )!;
            ArgBuilder oArg = ilg.GetArg("o");
            ilg.LdargAddress(oArg);
            ilg.ConvertAddress(oArg.ArgType, typeof(object));
            ilg.Call(Object_GetType);
            ilg.Stloc(tLoc);
            WriteTypeCompare("t", mapping.TypeDesc.Type!);
            // Bool on the stack from WriteTypeCompare.
            ilg.If(); // if (t == typeof(...))
            WriteDerivedTypes(mapping);
            if (mapping.TypeDesc.IsRoot)
                WriteEnumAndArrayTypes();
            ilg.Else();
            if (mapping.TypeDesc.IsRoot)
            {
                MethodInfo XmlSerializationWriter_WriteTypedPrimitive = typeof(XmlSerializationWriter).GetMethod(
                        "WriteTypedPrimitive",
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { typeof(string), typeof(string), typeof(object), typeof(bool) }
                        )!;
                ilg.Ldarg(0);
                ilg.Ldarg("n");
                ilg.Ldarg("ns");
                ilg.Ldarg("o");
                ilg.Ldc(true);
                ilg.Call(XmlSerializationWriter_WriteTypedPrimitive);
                ilg.GotoMethodEnd();
            }
            else
            {
                MethodInfo XmlSerializationWriter_CreateUnknownTypeException = typeof(XmlSerializationWriter).GetMethod(
                    "CreateUnknownTypeException",
                    CodeGenerator.InstanceBindingFlags,
                    s_objectType
                    )!;
                ilg.Ldarg(0);
                ilg.Ldarg(oArg);
                ilg.ConvertValue(oArg.ArgType, typeof(object));
                ilg.Call(XmlSerializationWriter_CreateUnknownTypeException);
                ilg.Throw();
            }
            ilg.EndIf(); // if (t == typeof(...))
            ilg.EndIf(); // if (!needType)

            if (!mapping.TypeDesc.IsAbstract)
            {
                if (mapping.TypeDesc.Type != null && typeof(XmlSchemaObject).IsAssignableFrom(mapping.TypeDesc.Type))
                {
                    MethodInfo XmlSerializationWriter_set_EscapeName = typeof(XmlSerializationWriter).GetMethod(
                        "set_EscapeName",
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { typeof(bool) }
                        )!;
                    ilg.Ldarg(0);
                    ilg.Ldc(false);
                    ilg.Call(XmlSerializationWriter_set_EscapeName);
                }

                string? xmlnsSource = null;
                MemberMapping[] members = TypeScope.GetAllMembers(mapping, memberInfos);
                int xmlnsMember = FindXmlnsIndex(members);
                if (xmlnsMember >= 0)
                {
                    MemberMapping member = members[xmlnsMember];
                    CodeIdentifier.CheckValidIdentifier(member.Name);
                    xmlnsSource = ReflectionAwareILGen.GetStringForMember("o", member.Name);
                }

                ilg.Ldarg(0);
                ilg.Ldarg("n");
                ilg.Ldarg("ns");
                ArgBuilder argO = ilg.GetArg("o");
                ilg.Ldarg(argO);
                ilg.ConvertValue(argO.ArgType, typeof(object));
                ilg.Ldc(false);
                if (xmlnsSource == null)
                    ilg.Load(null);
                else
                {
                    System.Diagnostics.Debug.Assert(xmlnsSource.StartsWith("o.@", StringComparison.Ordinal));
                    ILGenLoad(xmlnsSource);
                }

                MethodInfo XmlSerializationWriter_WriteStartElement = typeof(XmlSerializationWriter).GetMethod(
                        "WriteStartElement",
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { typeof(string), typeof(string), typeof(object), typeof(bool), typeof(XmlSerializerNamespaces) }
                        )!;
                ilg.Call(XmlSerializationWriter_WriteStartElement);
                if (!mapping.TypeDesc.IsRoot)
                {
                    ilg.If(ilg.GetArg("needType"), Cmp.EqualTo, true);
                    {
                        MethodInfo XmlSerializationWriter_WriteXsiType = typeof(XmlSerializationWriter).GetMethod(
                                "WriteXsiType",
                                CodeGenerator.InstanceBindingFlags,
                                new Type[] { typeof(string), typeof(string) }
                                )!;
                        ilg.Ldarg(0);
                        ilg.Ldstr(GetCSharpString(mapping.TypeName));
                        ilg.Ldstr(GetCSharpString(mapping.Namespace));
                        ilg.Call(XmlSerializationWriter_WriteXsiType);
                    }
                    ilg.EndIf();
                }
                for (int i = 0; i < members.Length; i++)
                {
                    MemberMapping m = members[i];
                    if (m.Attribute != null)
                    {
                        CodeIdentifier.CheckValidIdentifier(m.Name);
                        if (m.CheckShouldPersist)
                        {
                            ilg.LdargAddress(oArg);
                            ilg.Call(m.CheckShouldPersistMethodInfo!);
                            ilg.If();
                        }
                        if (m.CheckSpecified != SpecifiedAccessor.None)
                        {
                            string memberGet = ReflectionAwareILGen.GetStringForMember("o", $"{m.Name}Specified");
                            ILGenLoad(memberGet);
                            ilg.If();
                        }
                        WriteMember(ReflectionAwareILGen.GetSourceForMember("o", m, ilg), m.Attribute, m.TypeDesc!, "o");

                        if (m.CheckSpecified != SpecifiedAccessor.None)
                        {
                            ilg.EndIf();
                        }
                        if (m.CheckShouldPersist)
                        {
                            ilg.EndIf();
                        }
                    }
                }

                for (int i = 0; i < members.Length; i++)
                {
                    MemberMapping m = members[i];
                    if (m.Xmlns != null)
                        continue;
                    CodeIdentifier.CheckValidIdentifier(m.Name);
                    bool checkShouldPersist = m.CheckShouldPersist && (m.Elements!.Length > 0 || m.Text != null);

                    if (checkShouldPersist)
                    {
                        ilg.LdargAddress(oArg);
                        ilg.Call(m.CheckShouldPersistMethodInfo!);
                        ilg.If();
                    }
                    if (m.CheckSpecified != SpecifiedAccessor.None)
                    {
                        string memberGet = ReflectionAwareILGen.GetStringForMember("o", $"{m.Name}Specified");
                        ILGenLoad(memberGet);
                        ilg.If();
                    }

                    string? choiceSource = null;
                    if (m.ChoiceIdentifier != null)
                    {
                        CodeIdentifier.CheckValidIdentifier(m.ChoiceIdentifier.MemberName);
                        choiceSource = ReflectionAwareILGen.GetStringForMember("o", m.ChoiceIdentifier.MemberName);
                    }

                    WriteMember(ReflectionAwareILGen.GetSourceForMember("o", m, m.MemberInfo, ilg), choiceSource, m.ElementsSortedByDerivation!, m.Text, m.ChoiceIdentifier, m.TypeDesc!, true);

                    if (m.CheckSpecified != SpecifiedAccessor.None)
                    {
                        ilg.EndIf();
                    }
                    if (checkShouldPersist)
                    {
                        ilg.EndIf();
                    }
                }
                WriteEndElement("o");
            }
            ilg.EndMethod();
        }

        private bool CanOptimizeWriteListSequence(TypeDesc? listElementTypeDesc)
        {
            // check to see if we can write values of the attribute sequentially
            // currently we have only one data type (XmlQualifiedName) that we can not write "inline",
            // because we need to output xmlns:qx="..." for each of the qnames

            return (listElementTypeDesc != null && listElementTypeDesc != QnameTypeDesc);
        }

        private void WriteMember(SourceInfo source, AttributeAccessor attribute, TypeDesc memberTypeDesc, string parent)
        {
            if (memberTypeDesc.IsAbstract) return;
            if (memberTypeDesc.IsArrayLike)
            {
                string aVar = $"a{memberTypeDesc.Name}";
                string aiVar = $"ai{memberTypeDesc.Name}";
                string iVar = "i";
                string fullTypeName = memberTypeDesc.CSharpName;
                ilg.EnterScope();
                WriteArrayLocalDecl(fullTypeName, aVar, source, memberTypeDesc);
                if (memberTypeDesc.IsNullable)
                {
                    ilg.Ldloc(memberTypeDesc.Type!, aVar);
                    ilg.Load(null);
                    ilg.If(Cmp.NotEqualTo);
                }
                if (attribute.IsList)
                {
                    if (CanOptimizeWriteListSequence(memberTypeDesc.ArrayElementTypeDesc))
                    {
                        string? ns = attribute.Form == XmlSchemaForm.Qualified ? attribute.Namespace : string.Empty;
                        MethodInfo XmlSerializationWriter_get_Writer = typeof(XmlSerializationWriter).GetMethod(
                            "get_Writer",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlWriter_WriteStartAttribute = typeof(XmlWriter).GetMethod(
                            "WriteStartAttribute",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string), typeof(string), typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Load(null);
                        ilg.Ldstr(GetCSharpString(attribute.Name));
                        ilg.Ldstr(GetCSharpString(ns));
                        ilg.Call(XmlWriter_WriteStartAttribute);
                    }
                    else
                    {
                        LocalBuilder sbLoc = ilg.DeclareOrGetLocal(typeof(StringBuilder), "sb");
                        ConstructorInfo StringBuilder_ctor = typeof(StringBuilder).GetConstructor(
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.New(StringBuilder_ctor);
                        ilg.Stloc(sbLoc);
                    }
                }
                TypeDesc arrayElementTypeDesc = memberTypeDesc.ArrayElementTypeDesc!;

                if (memberTypeDesc.IsEnumerable)
                {
                    throw Globals.NotSupported("Also fail in IEnumerable member with XmlAttributeAttribute");
                }
                else
                {
                    LocalBuilder localI = ilg.DeclareOrGetLocal(typeof(int), iVar);
                    ilg.For(localI, 0, ilg.GetLocal(aVar));
                    WriteLocalDecl(aiVar, ReflectionAwareILGen.GetStringForArrayMember(aVar, iVar), arrayElementTypeDesc.Type!);
                }
                if (attribute.IsList)
                {
                    string methodName;
                    Type methodType;
                    Type argType;
                    // check to see if we can write values of the attribute sequentially
                    if (CanOptimizeWriteListSequence(memberTypeDesc.ArrayElementTypeDesc))
                    {
                        ilg.Ldloc(iVar);
                        ilg.Ldc(0);
                        ilg.If(Cmp.NotEqualTo);
                        MethodInfo XmlSerializationWriter_get_Writer = typeof(XmlSerializationWriter).GetMethod(
                            "get_Writer",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlWriter_WriteString = typeof(XmlWriter).GetMethod(
                            "WriteString",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Ldstr(" ");
                        ilg.Call(XmlWriter_WriteString);
                        ilg.EndIf();
                        ilg.Ldarg(0);
                        methodName = "WriteValue";
                        methodType = typeof(XmlSerializationWriter);
                    }
                    else
                    {
                        MethodInfo StringBuilder_Append = typeof(StringBuilder).GetMethod(
                            "Append",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string) }
                            )!;
                        ilg.Ldloc(iVar);
                        ilg.Ldc(0);
                        ilg.If(Cmp.NotEqualTo);
                        ilg.Ldloc("sb");
                        ilg.Ldstr(" ");
                        ilg.Call(StringBuilder_Append);
                        ilg.Pop();
                        ilg.EndIf();
                        ilg.Ldloc("sb");
                        methodName = "Append";
                        methodType = typeof(StringBuilder);
                    }
                    if (attribute.Mapping is EnumMapping)
                        WriteEnumValue((EnumMapping)attribute.Mapping, new SourceInfo(aiVar, aiVar, null, arrayElementTypeDesc.Type, ilg), out argType);
                    else
                        WritePrimitiveValue(arrayElementTypeDesc, new SourceInfo(aiVar, aiVar, null, arrayElementTypeDesc.Type, ilg), out argType);
                    MethodInfo method = methodType.GetMethod(
                        methodName,
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { argType }
                        )!;
                    ilg.Call(method);
                    if (method.ReturnType != typeof(void))
                        ilg.Pop();
                }
                else
                {
                    WriteAttribute(new SourceInfo(aiVar, aiVar, null, null, ilg), attribute, parent);
                }
                if (memberTypeDesc.IsEnumerable)
                    throw Globals.NotSupported("Also fail in whidbey IEnumerable member with XmlAttributeAttribute");
                else
                    ilg.EndFor();
                if (attribute.IsList)
                {
                    // check to see if we can write values of the attribute sequentially
                    if (CanOptimizeWriteListSequence(memberTypeDesc.ArrayElementTypeDesc))
                    {
                        MethodInfo XmlSerializationWriter_get_Writer = typeof(XmlSerializationWriter).GetMethod(
                            "get_Writer",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlWriter_WriteEndAttribute = typeof(XmlWriter).GetMethod(
                            "WriteEndAttribute",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Call(XmlWriter_WriteEndAttribute);
                    }
                    else
                    {
                        MethodInfo StringBuilder_get_Length = typeof(StringBuilder).GetMethod(
                            "get_Length",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Ldloc("sb");
                        ilg.Call(StringBuilder_get_Length);
                        ilg.Ldc(0);
                        ilg.If(Cmp.NotEqualTo);

                        List<Type> argTypes = new List<Type>();
                        ilg.Ldarg(0);
                        ilg.Ldstr(GetCSharpString(attribute.Name));
                        argTypes.Add(typeof(string));
                        string? ns = attribute.Form == XmlSchemaForm.Qualified ? attribute.Namespace : string.Empty;
                        if (ns != null)
                        {
                            ilg.Ldstr(GetCSharpString(ns));
                            argTypes.Add(typeof(string));
                        }
                        MethodInfo Object_ToString = typeof(object).GetMethod(
                            "ToString",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Ldloc("sb");
                        ilg.Call(Object_ToString);
                        argTypes.Add(typeof(string));
                        MethodInfo XmlSerializationWriter_WriteAttribute = typeof(XmlSerializationWriter).GetMethod(
                             "WriteAttribute",
                             CodeGenerator.InstanceBindingFlags,
                             argTypes.ToArray()
                             )!;
                        ilg.Call(XmlSerializationWriter_WriteAttribute);
                        ilg.EndIf();
                    }
                }

                if (memberTypeDesc.IsNullable)
                {
                    ilg.EndIf();
                }

                ilg.ExitScope();
            }
            else
            {
                WriteAttribute(source, attribute, parent);
            }
        }

        private void WriteAttribute(SourceInfo source, AttributeAccessor attribute, string parent)
        {
            if (attribute.Mapping is SpecialMapping special)
            {
                if (special.TypeDesc!.Kind == TypeKind.Attribute || special.TypeDesc.CanBeAttributeValue)
                {
                    System.Diagnostics.Debug.Assert(parent == "o" || parent == "p");
                    MethodInfo XmlSerializationWriter_WriteXmlAttribute = typeof(XmlSerializationWriter).GetMethod(
                        "WriteXmlAttribute",
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { typeof(XmlNode), typeof(object) }
                        )!;
                    ilg.Ldarg(0);
                    ilg.Ldloc(source.Source);
                    ilg.Ldarg(parent);
                    ilg.ConvertValue(ilg.GetArg(parent).ArgType, typeof(object));
                    ilg.Call(XmlSerializationWriter_WriteXmlAttribute);
                }
                else
                    throw new InvalidOperationException(SR.XmlInternalError);
            }
            else
            {
                TypeDesc typeDesc = attribute.Mapping!.TypeDesc!;
                source = source.CastTo(typeDesc);
                WritePrimitive("WriteAttribute", attribute.Name, attribute.Form == XmlSchemaForm.Qualified ? attribute.Namespace : "", GetConvertedDefaultValue(source.Type, attribute.Default), source, attribute.Mapping, false, false, false);
            }
        }

        private static object? GetConvertedDefaultValue(
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicMethods)]
            Type? targetType,
            object? rawDefaultValue)
        {
            if (targetType == null)
            {
                return rawDefaultValue;
            }

            object? convertedDefaultValue;
            if (!targetType.TryConvertTo(rawDefaultValue, out convertedDefaultValue))
            {
                return rawDefaultValue;
            }

            return convertedDefaultValue;
        }

        private void WriteMember(SourceInfo source, string? choiceSource, ElementAccessor[] elements, TextAccessor? text, ChoiceIdentifierAccessor? choice, TypeDesc memberTypeDesc, bool writeAccessors)
        {
            if (memberTypeDesc.IsArrayLike &&
                !(elements.Length == 1 && elements[0].Mapping is ArrayMapping))
                WriteArray(source, choiceSource, elements, text, choice, memberTypeDesc);
            else
                // NOTE: Use different variable name to work around reuse same variable name in different scope
                WriteElements(source, choiceSource, elements, text, choice, $"a{memberTypeDesc.Name}", writeAccessors, memberTypeDesc.IsNullable);
        }

        private void WriteArray(SourceInfo source, string? choiceSource, ElementAccessor[] elements, TextAccessor? text, ChoiceIdentifierAccessor? choice, TypeDesc arrayTypeDesc)
        {
            if (elements.Length == 0 && text == null) return;
            string arrayTypeName = arrayTypeDesc.CSharpName;
            string aName = $"a{arrayTypeDesc.Name}";
            ilg.EnterScope();
            WriteArrayLocalDecl(arrayTypeName, aName, source, arrayTypeDesc);
            LocalBuilder aLoc = ilg.GetLocal(aName);
            if (arrayTypeDesc.IsNullable)
            {
                ilg.Ldloc(aLoc);
                ilg.Load(null);
                ilg.If(Cmp.NotEqualTo);
            }

            string? cName = null;
            if (choice != null)
            {
                string choiceFullName = choice.Mapping!.TypeDesc!.CSharpName;
                SourceInfo choiceSourceInfo = new SourceInfo(choiceSource!, null, choice.MemberInfo, null, ilg);
                cName = $"c{choice.Mapping.TypeDesc.Name}";
                WriteArrayLocalDecl($"{choiceFullName}[]", cName, choiceSourceInfo, choice.Mapping.TypeDesc);
                // write check for the choice identifier array
                Label labelEnd = ilg.DefineLabel();
                Label labelTrue = ilg.DefineLabel();
                LocalBuilder cLoc = ilg.GetLocal(cName);
                ilg.Ldloc(cLoc);
                ilg.Load(null);
                ilg.Beq(labelTrue);
                ilg.Ldloc(cLoc);
                ilg.Ldlen();
                ilg.Ldloc(aLoc);
                ilg.Ldlen();
                ilg.Clt();
                ilg.Br(labelEnd);
                ilg.MarkLabel(labelTrue);
                ilg.Ldc(true);
                ilg.MarkLabel(labelEnd);
                ilg.If();
                MethodInfo XmlSerializationWriter_CreateInvalidChoiceIdentifierValueException = typeof(XmlSerializationWriter).GetMethod(
                    "CreateInvalidChoiceIdentifierValueException",
                    CodeGenerator.InstanceBindingFlags,
                    new Type[] { typeof(string), typeof(string) }
                    )!;
                ilg.Ldarg(0);
                ilg.Ldstr(GetCSharpString(choice.Mapping.TypeDesc.FullName));
                ilg.Ldstr(GetCSharpString(choice.MemberName));
                ilg.Call(XmlSerializationWriter_CreateInvalidChoiceIdentifierValueException);
                ilg.Throw();
                ilg.EndIf();
            }

            WriteArrayItems(elements, text, choice, arrayTypeDesc, aName, cName!);
            if (arrayTypeDesc.IsNullable)
            {
                ilg.EndIf();
            }

            ilg.ExitScope();
        }

        private void WriteArrayItems(ElementAccessor[] elements, TextAccessor? text, ChoiceIdentifierAccessor? choice, TypeDesc arrayTypeDesc, string arrayName, string? choiceName)
        {
            TypeDesc arrayElementTypeDesc = arrayTypeDesc.ArrayElementTypeDesc!;

            if (arrayTypeDesc.IsEnumerable)
            {
                LocalBuilder eLoc = ilg.DeclareLocal(typeof(IEnumerator), "e");
                ilg.LoadAddress(ilg.GetVariable(arrayName));
                MethodInfo getEnumeratorMethod;

                if (arrayTypeDesc.IsPrivateImplementation)
                {
                    Type typeIEnumerable = typeof(IEnumerable);

                    getEnumeratorMethod = typeIEnumerable.GetMethod(
                        "GetEnumerator",
                        CodeGenerator.InstanceBindingFlags,
                        Type.EmptyTypes)!;

                    ilg.ConvertValue(arrayTypeDesc.Type!, typeIEnumerable);
                }
                else if (arrayTypeDesc.IsGenericInterface)
                {
                    Type typeIEnumerable = typeof(IEnumerable<>).MakeGenericType(arrayElementTypeDesc.Type!);

                    getEnumeratorMethod = typeIEnumerable.GetMethod(
                        "GetEnumerator",
                        CodeGenerator.InstanceBindingFlags,
                        Type.EmptyTypes)!;

                    ilg.ConvertValue(arrayTypeDesc.Type!, typeIEnumerable);
                }
                else
                {
                    getEnumeratorMethod = arrayTypeDesc.Type!.GetMethod(
                        "GetEnumerator",
                        Type.EmptyTypes)!;
                }
                ilg.Call(getEnumeratorMethod);
                ilg.ConvertValue(getEnumeratorMethod.ReturnType, typeof(IEnumerator));
                ilg.Stloc(eLoc);

                ilg.Ldloc(eLoc);
                ilg.Load(null);
                ilg.If(Cmp.NotEqualTo);
                ilg.WhileBegin();
                string arrayNamePlusA = $"{(arrayName).Replace(arrayTypeDesc.Name, "")}a{arrayElementTypeDesc.Name}";
                string arrayNamePlusI = $"{(arrayName).Replace(arrayTypeDesc.Name, "")}i{arrayElementTypeDesc.Name}";
                WriteLocalDecl(arrayNamePlusI, "e.Current", arrayElementTypeDesc.Type!);
                WriteElements(new SourceInfo(arrayNamePlusI, null, null, arrayElementTypeDesc.Type, ilg), $"{choiceName}i", elements, text, choice, arrayNamePlusA, true, true);

                ilg.WhileBeginCondition(); // while (e.MoveNext())
                MethodInfo IEnumerator_MoveNext = typeof(IEnumerator).GetMethod(
                    "MoveNext",
                    CodeGenerator.InstanceBindingFlags,
                    Type.EmptyTypes)!;
                ilg.Ldloc(eLoc);
                ilg.Call(IEnumerator_MoveNext);
                ilg.WhileEndCondition();
                ilg.WhileEnd();

                ilg.EndIf(); // if (e != null)
            }
            else
            {
                // Filter out type specific for index (code match reusing local).
                string iPlusArrayName = $"i{(arrayName).Replace(arrayTypeDesc.Name, "")}";
                string arrayNamePlusA = $"{(arrayName).Replace(arrayTypeDesc.Name, "")}a{arrayElementTypeDesc.Name}";
                string arrayNamePlusI = $"{(arrayName).Replace(arrayTypeDesc.Name, "")}i{arrayElementTypeDesc.Name}";
                LocalBuilder localI = ilg.DeclareOrGetLocal(typeof(int), iPlusArrayName);
                ilg.For(localI, 0, ilg.GetLocal(arrayName));
                int count = elements.Length + (text == null ? 0 : 1);
                if (count > 1)
                {
                    WriteLocalDecl(arrayNamePlusI, ReflectionAwareILGen.GetStringForArrayMember(arrayName, iPlusArrayName), arrayElementTypeDesc.Type!);
                    if (choice != null)
                    {
                        WriteLocalDecl($"{choiceName}i", ReflectionAwareILGen.GetStringForArrayMember(choiceName, iPlusArrayName), choice.Mapping!.TypeDesc!.Type!);
                    }
                    WriteElements(new SourceInfo(arrayNamePlusI, null, null, arrayElementTypeDesc.Type, ilg), $"{choiceName}i", elements, text, choice, arrayNamePlusA, true, arrayElementTypeDesc.IsNullable);
                }
                else
                {
                    WriteElements(new SourceInfo(ReflectionAwareILGen.GetStringForArrayMember(arrayName, iPlusArrayName), null, null, arrayElementTypeDesc.Type, ilg), null, elements, text, choice, arrayNamePlusA, true, arrayElementTypeDesc.IsNullable);
                }
                ilg.EndFor();
            }
        }

        private void WriteElements(SourceInfo source, string? enumSource, ElementAccessor[] elements, TextAccessor? text, ChoiceIdentifierAccessor? choice, string arrayName, bool writeAccessors, bool isNullable)
        {
            if (elements.Length == 0 && text == null) return;
            if (elements.Length == 1 && text == null)
            {
                TypeDesc td = elements[0].IsUnbounded ? elements[0].Mapping!.TypeDesc!.CreateArrayTypeDesc() : elements[0].Mapping!.TypeDesc!;
                if (!elements[0].Any && !elements[0].Mapping!.TypeDesc!.IsOptionalValue)
                    source = source.CastTo(td);
                WriteElement(source, elements[0], arrayName, writeAccessors);
            }
            else
            {
                bool doEndIf = false;
                if (isNullable && choice == null)
                {
                    source.Load(typeof(object));
                    ilg.Load(null);
                    ilg.If(Cmp.NotEqualTo);
                    doEndIf = true;
                }
                int anyCount = 0;
                var namedAnys = new List<ElementAccessor>();
                ElementAccessor? unnamedAny = null; // can only have one
                bool wroteFirstIf = false;
                string? enumTypeName = choice == null ? null : choice.Mapping!.TypeDesc!.FullName;

                for (int i = 0; i < elements.Length; i++)
                {
                    ElementAccessor element = elements[i];

                    if (element.Any)
                    {
                        anyCount++;
                        if (element.Name != null && element.Name.Length > 0)
                        {
                            namedAnys.Add(element);
                        }
                        else
                        {
                            unnamedAny ??= element;
                        }
                    }
                    else if (choice != null)
                    {
                        object? enumValue;
                        string enumFullName = $"{enumTypeName}.@{FindChoiceEnumValue(element, (EnumMapping)choice.Mapping!, out enumValue)}";

                        if (wroteFirstIf) ilg.InitElseIf();
                        else { wroteFirstIf = true; ilg.InitIf(); }
                        ILGenLoad(enumSource!, choice == null ? null : choice.Mapping!.TypeDesc!.Type);
                        ilg.Load(enumValue);
                        ilg.Ceq();
                        if (isNullable && !element.IsNullable)
                        {
                            Label labelFalse = ilg.DefineLabel();
                            Label labelEnd = ilg.DefineLabel();
                            ilg.Brfalse(labelFalse);
                            source.Load(typeof(object));
                            ilg.Load(null);
                            ilg.Cne();
                            ilg.Br_S(labelEnd);
                            ilg.MarkLabel(labelFalse);
                            ilg.Ldc(false);
                            ilg.MarkLabel(labelEnd);
                        }
                        ilg.AndIf();

                        WriteChoiceTypeCheck(source, choice!, enumFullName, element.Mapping!.TypeDesc!);

                        SourceInfo castedSource = source.CastTo(element.Mapping.TypeDesc!);
                        WriteElement(element.Any ? source : castedSource, element, arrayName, writeAccessors);
                    }
                    else
                    {
                        TypeDesc td = element.IsUnbounded ? element.Mapping!.TypeDesc!.CreateArrayTypeDesc() : element.Mapping!.TypeDesc!;
                        if (wroteFirstIf) ilg.InitElseIf();
                        else { wroteFirstIf = true; ilg.InitIf(); }
                        WriteInstanceOf(source, td.Type!);
                        // WriteInstanceOf leave bool on the stack
                        ilg.AndIf();
                        SourceInfo castedSource = source.CastTo(td);
                        WriteElement(element.Any ? source : castedSource, element, arrayName, writeAccessors);
                    }
                }
                if (wroteFirstIf)
                {
                    if (anyCount > 0)
                    {
                        // See "else " below
                        if (elements.Length - anyCount > 0)
                        { // NOOP
                        }
                        else ilg.EndIf();
                    }
                }
                if (anyCount > 0)
                {
                    if (elements.Length - anyCount > 0) ilg.InitElseIf();
                    else ilg.InitIf();

                    source.Load(typeof(object));
                    ilg.IsInst(typeof(XmlElement));
                    ilg.Load(null);
                    ilg.Cne();
                    ilg.AndIf();

                    LocalBuilder elemLoc = ilg.DeclareLocal(typeof(XmlElement), "elem");
                    source.Load(typeof(XmlElement));
                    ilg.Stloc(elemLoc);

                    int c = 0;

                    foreach (ElementAccessor element in namedAnys)
                    {
                        if (c++ > 0) ilg.InitElseIf();
                        else ilg.InitIf();

                        string? enumFullName = null;

                        Label labelEnd, labelFalse;
                        if (choice != null)
                        {
                            object? enumValue;
                            enumFullName = $"{enumTypeName}.@{FindChoiceEnumValue(element, (EnumMapping)choice.Mapping!, out enumValue)}";
                            labelFalse = ilg.DefineLabel();
                            labelEnd = ilg.DefineLabel();
                            ILGenLoad(enumSource!, choice == null ? null : choice.Mapping!.TypeDesc!.Type);
                            ilg.Load(enumValue);
                            ilg.Bne(labelFalse);
                            if (isNullable && !element.IsNullable)
                            {
                                source.Load(typeof(object));
                                ilg.Load(null);
                                ilg.Cne();
                            }
                            else
                            {
                                ilg.Ldc(true);
                            }
                            ilg.Br(labelEnd);
                            ilg.MarkLabel(labelFalse);
                            ilg.Ldc(false);
                            ilg.MarkLabel(labelEnd);
                            ilg.AndIf();
                        }
                        labelFalse = ilg.DefineLabel();
                        labelEnd = ilg.DefineLabel();
                        MethodInfo XmlNode_get_Name = typeof(XmlNode).GetMethod(
                            "get_Name",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlNode_get_NamespaceURI = typeof(XmlNode).GetMethod(
                            "get_NamespaceURI",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Ldloc(elemLoc);
                        ilg.Call(XmlNode_get_Name);
                        ilg.Ldstr(GetCSharpString(element.Name));
                        MethodInfo String_op_Equality = typeof(string).GetMethod(
                            "op_Equality",
                            CodeGenerator.StaticBindingFlags,
                            new Type[] { typeof(string), typeof(string) }
                            )!;
                        ilg.Call(String_op_Equality);
                        ilg.Brfalse(labelFalse);
                        ilg.Ldloc(elemLoc);
                        ilg.Call(XmlNode_get_NamespaceURI);
                        ilg.Ldstr(GetCSharpString(element.Namespace));
                        ilg.Call(String_op_Equality);
                        ilg.Br(labelEnd);
                        ilg.MarkLabel(labelFalse);
                        ilg.Ldc(false);
                        ilg.MarkLabel(labelEnd);
                        if (choice != null) ilg.If();
                        else ilg.AndIf();
                        WriteElement(new SourceInfo("elem", null, null, elemLoc.LocalType, ilg), element, arrayName, writeAccessors);

                        if (choice != null)
                        {
                            ilg.Else();

                            MethodInfo XmlSerializationWriter_CreateChoiceIdentifierValueException = typeof(XmlSerializationWriter).GetMethod(
                                "CreateChoiceIdentifierValueException",
                                CodeGenerator.InstanceBindingFlags,
                                new Type[] { typeof(string), typeof(string), typeof(string), typeof(string) }
                                )!;
                            ilg.Ldarg(0);
                            ilg.Ldstr(GetCSharpString(enumFullName));
                            ilg.Ldstr(GetCSharpString(choice.MemberName));
                            ilg.Ldloc(elemLoc);
                            ilg.Call(XmlNode_get_Name);
                            ilg.Ldloc(elemLoc);
                            ilg.Call(XmlNode_get_NamespaceURI);
                            ilg.Call(XmlSerializationWriter_CreateChoiceIdentifierValueException);
                            ilg.Throw();
                            ilg.EndIf();
                        }
                    }
                    if (c > 0)
                    {
                        ilg.Else();
                    }
                    if (unnamedAny != null)
                    {
                        WriteElement(new SourceInfo("elem", null, null, elemLoc.LocalType, ilg), unnamedAny, arrayName, writeAccessors);
                    }
                    else
                    {
                        MethodInfo XmlSerializationWriter_CreateUnknownAnyElementException = typeof(XmlSerializationWriter).GetMethod(
                            "CreateUnknownAnyElementException",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(string), typeof(string) }
                            )!;
                        ilg.Ldarg(0);
                        ilg.Ldloc(elemLoc);
                        MethodInfo XmlNode_get_Name = typeof(XmlNode).GetMethod(
                            "get_Name",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        MethodInfo XmlNode_get_NamespaceURI = typeof(XmlNode).GetMethod(
                            "get_NamespaceURI",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        ilg.Call(XmlNode_get_Name);
                        ilg.Ldloc(elemLoc);
                        ilg.Call(XmlNode_get_NamespaceURI);
                        ilg.Call(XmlSerializationWriter_CreateUnknownAnyElementException);
                        ilg.Throw();
                    }
                    if (c > 0)
                    {
                        ilg.EndIf();
                    }
                }
                if (text != null)
                {
                    if (elements.Length > 0)
                    {
                        ilg.InitElseIf();
                        WriteInstanceOf(source, text.Mapping!.TypeDesc!.Type!);
                        ilg.AndIf();
                        SourceInfo castedSource = source.CastTo(text.Mapping.TypeDesc);
                        WriteText(castedSource, text);
                    }
                    else
                    {
                        SourceInfo castedSource = source.CastTo(text.Mapping!.TypeDesc!);
                        WriteText(castedSource, text);
                    }
                }
                if (elements.Length > 0)
                {
                    if (isNullable)
                    {
                        ilg.InitElseIf();
                        source.Load(null);
                        ilg.Load(null);
                        ilg.AndIf(Cmp.NotEqualTo);
                    }
                    else
                    {
                        ilg.Else();
                    }

                    MethodInfo XmlSerializationWriter_CreateUnknownTypeException = typeof(XmlSerializationWriter).GetMethod(
                        "CreateUnknownTypeException",
                        CodeGenerator.InstanceBindingFlags,
                        s_objectType)!;
                    ilg.Ldarg(0);
                    source.Load(typeof(object));
                    ilg.Call(XmlSerializationWriter_CreateUnknownTypeException);
                    ilg.Throw();

                    ilg.EndIf();
                }
                // See ilg.If() cond above
                if (doEndIf) // if (isNullable && choice == null)
                    ilg.EndIf();
            }
        }

        private void WriteText(SourceInfo source, TextAccessor text)
        {
            if (text.Mapping is PrimitiveMapping primitiveMapping)
            {
                Type argType;
                ilg.Ldarg(0);
                if (text.Mapping is EnumMapping)
                {
                    WriteEnumValue((EnumMapping)text.Mapping, source, out argType);
                }
                else
                {
                    WritePrimitiveValue(primitiveMapping.TypeDesc!, source, out argType);
                }
                MethodInfo XmlSerializationWriter_WriteValue = typeof(XmlSerializationWriter).GetMethod(
                    "WriteValue",
                    CodeGenerator.InstanceBindingFlags,
                    new Type[] { argType }
                    )!;
                ilg.Call(XmlSerializationWriter_WriteValue);
            }
            else if (text.Mapping is SpecialMapping specialMapping)
            {
                switch (specialMapping.TypeDesc!.Kind)
                {
                    case TypeKind.Node:
                        MethodInfo WriteTo = source.Type!.GetMethod(
                            "WriteTo",
                            CodeGenerator.InstanceBindingFlags,
                            new Type[] { typeof(XmlWriter) }
                            )!;
                        MethodInfo XmlSerializationWriter_get_Writer = typeof(XmlSerializationWriter).GetMethod(
                            "get_Writer",
                            CodeGenerator.InstanceBindingFlags,
                            Type.EmptyTypes
                            )!;
                        source.Load(source.Type);
                        ilg.Ldarg(0);
                        ilg.Call(XmlSerializationWriter_get_Writer);
                        ilg.Call(WriteTo);
                        break;
                    default:
                        throw new InvalidOperationException(SR.XmlInternalError);
                }
            }
        }

        private void WriteElement(SourceInfo source, ElementAccessor element, string arrayName, bool writeAccessor)
        {
            string name = writeAccessor ? element.Name : element.Mapping!.TypeName!;
            string? ns = element.Any && element.Name.Length == 0 ? null : (element.Form == XmlSchemaForm.Qualified ? (writeAccessor ? element.Namespace : element.Mapping!.Namespace) : "");
            if (element.Mapping is NullableMapping)
            {
                if (source.Type == element.Mapping.TypeDesc!.Type)
                {
                    MethodInfo Nullable_get_HasValue = element.Mapping.TypeDesc.Type!.GetMethod(
                        "get_HasValue",
                        CodeGenerator.InstanceBindingFlags,
                        Type.EmptyTypes
                        )!;
                    source.LoadAddress(element.Mapping.TypeDesc.Type);
                    ilg.Call(Nullable_get_HasValue);
                }
                else
                {
                    source.Load(null);
                    ilg.Load(null);
                    ilg.Cne();
                }
                ilg.If();
                SourceInfo castedSource = source.CastTo(element.Mapping.TypeDesc.BaseTypeDesc!);
                ElementAccessor e = element.Clone();
                e.Mapping = ((NullableMapping)element.Mapping).BaseMapping;
                WriteElement(e.Any ? source : castedSource, e, arrayName, writeAccessor);
                if (element.IsNullable)
                {
                    ilg.Else();
                    WriteLiteralNullTag(element.Name, element.Form == XmlSchemaForm.Qualified ? element.Namespace : "");
                }
                ilg.EndIf();
            }
            else if (element.Mapping is ArrayMapping arrayMapping)
            {
                if (element.IsUnbounded)
                {
                    throw Globals.NotSupported("Unreachable: IsUnbounded is never set true!");
                }
                else
                {
                    ilg.EnterScope();
                    string fullTypeName = arrayMapping.TypeDesc!.CSharpName;
                    WriteArrayLocalDecl(fullTypeName, arrayName, source, arrayMapping.TypeDesc);
                    if (element.IsNullable)
                    {
                        WriteNullCheckBegin(arrayName, element);
                    }
                    else
                    {
                        if (arrayMapping.TypeDesc.IsNullable)
                        {
                            ilg.Ldloc(ilg.GetLocal(arrayName));
                            ilg.Load(null);
                            ilg.If(Cmp.NotEqualTo);
                        }
                    }
                    WriteStartElement(name, ns, false);
                    WriteArrayItems(arrayMapping.ElementsSortedByDerivation!, null, null, arrayMapping.TypeDesc, arrayName, null);
                    WriteEndElement();
                    if (element.IsNullable)
                    {
                        ilg.EndIf();
                    }
                    else
                    {
                        if (arrayMapping.TypeDesc.IsNullable)
                        {
                            ilg.EndIf();
                        }
                    }
                    ilg.ExitScope();
                }
            }
            else if (element.Mapping is EnumMapping)
            {
                WritePrimitive("WriteElementString", name, ns, element.Default, source, element.Mapping, false, true, element.IsNullable);
            }
            else if (element.Mapping is PrimitiveMapping primitiveMapping)
            {
                if (primitiveMapping.TypeDesc == QnameTypeDesc)
                {
                    WriteQualifiedNameElement(name, ns, GetConvertedDefaultValue(source.Type, element.Default), source, element.IsNullable, primitiveMapping);
                }
                else
                {
                    string suffixRaw = primitiveMapping.TypeDesc!.XmlEncodingNotRequired ? "Raw" : "";
                    WritePrimitive(element.IsNullable ? ("WriteNullableStringLiteral" + suffixRaw) : ("WriteElementString" + suffixRaw),
                                   name, ns, GetConvertedDefaultValue(source.Type, element.Default), source, primitiveMapping, false, true, element.IsNullable);
                }
            }
            else if (element.Mapping is StructMapping structMapping)
            {
                string? methodName = ReferenceMapping(structMapping);

#if DEBUG
                // use exception in the place of Debug.Assert to avoid throwing asserts from a server process such as aspnet_ewp.exe
                if (methodName == null) throw new InvalidOperationException(SR.Format(SR.XmlInternalErrorMethod, structMapping.TypeDesc!.Name));
#endif
                List<Type> argTypes = new List<Type>();
                ilg.Ldarg(0);
                ilg.Ldstr(GetCSharpString(name));
                argTypes.Add(typeof(string));
                ilg.Ldstr(GetCSharpString(ns));
                argTypes.Add(typeof(string));
                source.Load(structMapping.TypeDesc!.Type);
                argTypes.Add(structMapping.TypeDesc.Type!);
                if (structMapping.TypeDesc.IsNullable)
                {
                    ilg.Ldc(element.IsNullable);
                    argTypes.Add(typeof(bool));
                }
                ilg.Ldc(false);
                argTypes.Add(typeof(bool));
                MethodBuilder methodBuilder = EnsureMethodBuilder(typeBuilder,
                    methodName!,
                    CodeGenerator.PrivateMethodAttributes,
                    typeof(void),
                    argTypes.ToArray());
                ilg.Call(methodBuilder);
            }
            else if (element.Mapping is SpecialMapping)
            {
                if (element.Mapping is SerializableMapping)
                {
                    WriteElementCall("WriteSerializable", typeof(IXmlSerializable), source, name, ns, element.IsNullable, !element.Any);
                }
                else
                {
                    // XmlNode, XmlElement
                    Label ifLabel1 = ilg.DefineLabel();
                    Label ifLabel2 = ilg.DefineLabel();
                    source.Load(null);
                    ilg.IsInst(typeof(XmlNode));
                    ilg.Brtrue(ifLabel1);
                    source.Load(null);
                    ilg.Load(null);
                    ilg.Ceq();
                    ilg.Br(ifLabel2);
                    ilg.MarkLabel(ifLabel1);
                    ilg.Ldc(true);
                    ilg.MarkLabel(ifLabel2);
                    ilg.If();

                    WriteElementCall("WriteElementLiteral", typeof(XmlNode), source, name, ns, element.IsNullable, element.Any);

                    ilg.Else();

                    MethodInfo XmlSerializationWriter_CreateInvalidAnyTypeException = typeof(XmlSerializationWriter).GetMethod(
                        "CreateInvalidAnyTypeException",
                        CodeGenerator.InstanceBindingFlags,
                        s_objectType
                        )!;
                    ilg.Ldarg(0);
                    source.Load(null);
                    ilg.Call(XmlSerializationWriter_CreateInvalidAnyTypeException);
                    ilg.Throw();

                    ilg.EndIf();
                }
            }
            else
            {
                throw new InvalidOperationException(SR.XmlInternalError);
            }
        }

        private void WriteElementCall(string func, Type cast, SourceInfo source, string? name, string? ns, bool isNullable, bool isAny)
        {
            MethodInfo XmlSerializationWriter_func = typeof(XmlSerializationWriter).GetMethod(
                 func,
                 CodeGenerator.InstanceBindingFlags,
                 new Type[] { cast, typeof(string), typeof(string), typeof(bool), typeof(bool) }
                 )!;
            ilg.Ldarg(0);
            source.Load(cast);
            ilg.Ldstr(GetCSharpString(name));
            ilg.Ldstr(GetCSharpString(ns));
            ilg.Ldc(isNullable);
            ilg.Ldc(isAny);
            ilg.Call(XmlSerializationWriter_func);
        }

        private void WriteCheckDefault(SourceInfo source, object value, bool isNullable)
        {
            if (value is string && ((string)value).Length == 0)
            {
                // special case for string compare
                Label labelEnd = ilg.DefineLabel();
                Label labelFalse = ilg.DefineLabel();
                Label labelTrue = ilg.DefineLabel();
                source.Load(typeof(string));
                if (isNullable)
                    // check == null with false
                    ilg.Brfalse(labelTrue);
                else
                    //check != null with false
                    ilg.Brfalse(labelFalse);
                MethodInfo String_get_Length = typeof(string).GetMethod(
                    "get_Length",
                    CodeGenerator.InstanceBindingFlags,
                    Type.EmptyTypes
                    )!;
                source.Load(typeof(string));
                ilg.Call(String_get_Length);
                ilg.Ldc(0);
                ilg.Cne();
                ilg.Br(labelEnd);
                if (isNullable)
                {
                    ilg.MarkLabel(labelTrue);
                    ilg.Ldc(true);
                }
                else
                {
                    ilg.MarkLabel(labelFalse);
                    ilg.Ldc(false);
                }
                ilg.MarkLabel(labelEnd);
                ilg.If();
            }
            else
            {
                if (value == null)
                {
                    source.Load(typeof(object));
                    ilg.Load(null);
                    ilg.Cne();
                }
                else if (value.GetType().IsPrimitive)
                {
                    source.Load(null);
                    ilg.Ldc(Convert.ChangeType(value, source.Type!, CultureInfo.InvariantCulture));
                    ilg.Cne();
                }
                else
                {
                    Type valueType = value.GetType();
                    source.Load(valueType);
                    ilg.Ldc(value is string ? GetCSharpString((string)value) : value);
                    MethodInfo op_Inequality = valueType.GetMethod(
                                "op_Inequality",
                                CodeGenerator.StaticBindingFlags,
                                new Type[] { valueType, valueType }
                                )!;
                    if (op_Inequality != null)
                        ilg.Call(op_Inequality);
                    else
                        ilg.Cne();
                }
                ilg.If();
            }
        }

        private void WriteChoiceTypeCheck(SourceInfo source, ChoiceIdentifierAccessor choice, string enumName, TypeDesc typeDesc)
        {
            Label labelFalse = ilg.DefineLabel();
            Label labelEnd = ilg.DefineLabel();
            source.Load(typeof(object));
            ilg.Load(null);
            ilg.Beq(labelFalse);
            WriteInstanceOf(source, typeDesc.Type!);
            // Negative
            ilg.Ldc(false);
            ilg.Ceq();
            ilg.Br(labelEnd);
            ilg.MarkLabel(labelFalse);
            ilg.Ldc(false);
            ilg.MarkLabel(labelEnd);
            ilg.If();
            MethodInfo XmlSerializationWriter_CreateMismatchChoiceException = typeof(XmlSerializationWriter).GetMethod(
                "CreateMismatchChoiceException",
                CodeGenerator.InstanceBindingFlags,
                new Type[] { typeof(string), typeof(string), typeof(string) }
                )!;
            ilg.Ldarg(0);
            ilg.Ldstr(GetCSharpString(typeDesc.FullName));
            ilg.Ldstr(GetCSharpString(choice.MemberName));
            ilg.Ldstr(GetCSharpString(enumName));
            ilg.Call(XmlSerializationWriter_CreateMismatchChoiceException);
            ilg.Throw();
            ilg.EndIf();
        }

        private void WriteNullCheckBegin(string source, ElementAccessor element)
        {
            LocalBuilder local = ilg.GetLocal(source);
            Debug.Assert(!local.LocalType.IsValueType);
            ilg.Load(local);
            ilg.Load(null);
            ilg.If(Cmp.EqualTo);
            WriteLiteralNullTag(element.Name, element.Form == XmlSchemaForm.Qualified ? element.Namespace : "");
            ilg.Else();
        }

        private void WriteNamespaces(string source)
        {
            MethodInfo XmlSerializationWriter_WriteNamespaceDeclarations = typeof(XmlSerializationWriter).GetMethod(
                "WriteNamespaceDeclarations",
                CodeGenerator.InstanceBindingFlags,
                new Type[] { typeof(XmlSerializerNamespaces) }
                )!;
            ilg.Ldarg(0);
            ILGenLoad(source, typeof(XmlSerializerNamespaces));
            ilg.Call(XmlSerializationWriter_WriteNamespaceDeclarations);
        }

        private static int FindXmlnsIndex(MemberMapping[] members)
        {
            for (int i = 0; i < members.Length; i++)
            {
                if (members[i].Xmlns == null)
                    continue;
                return i;
            }
            return -1;
        }

        private void WriteLocalDecl(string variableName, string initValue, Type type)
        {
            ReflectionAwareILGen.WriteLocalDecl(variableName, new SourceInfo(initValue, initValue, null, type, ilg));
        }

        private static void WriteArrayLocalDecl(string typeName, string variableName, SourceInfo initValue, TypeDesc arrayTypeDesc)
        {
            ReflectionAwareILGen.WriteArrayLocalDecl(typeName, variableName, initValue, arrayTypeDesc);
        }
        private void WriteTypeCompare(string variable, Type type)
        {
            ReflectionAwareILGen.WriteTypeCompare(variable, type, ilg);
        }

        private void WriteInstanceOf(SourceInfo source, Type type)
        {
            ReflectionAwareILGen.WriteInstanceOf(source, type, ilg);
        }
        private void WriteArrayTypeCompare(string variable, Type arrayType)
        {
            ReflectionAwareILGen.WriteArrayTypeCompare(variable, arrayType, ilg);
        }


        private static string FindChoiceEnumValue(ElementAccessor element, EnumMapping choiceMapping, out object? eValue)
        {
            string? enumValue = null;
            eValue = null;

            for (int i = 0; i < choiceMapping.Constants!.Length; i++)
            {
                string xmlName = choiceMapping.Constants[i].XmlName;

                if (element.Any && element.Name.Length == 0)
                {
                    if (xmlName == "##any:")
                    {
                        enumValue = choiceMapping.Constants[i].Name;
                        eValue = Enum.ToObject(choiceMapping.TypeDesc!.Type!, choiceMapping.Constants[i].Value);
                        break;
                    }
                    continue;
                }
                int colon = xmlName.LastIndexOf(':');
                string? choiceNs = colon < 0 ? choiceMapping.Namespace : xmlName.Substring(0, colon);
                string choiceName = colon < 0 ? xmlName : xmlName.Substring(colon + 1);

                if (element.Name == choiceName)
                {
                    if ((element.Form == XmlSchemaForm.Unqualified && string.IsNullOrEmpty(choiceNs)) || element.Namespace == choiceNs)
                    {
                        enumValue = choiceMapping.Constants[i].Name;
                        eValue = Enum.ToObject(choiceMapping.TypeDesc!.Type!, choiceMapping.Constants[i].Value);
                        break;
                    }
                }
            }
            if (string.IsNullOrEmpty(enumValue))
            {
                if (element.Any && element.Name.Length == 0)
                {
                    // Type {0} is missing enumeration value '##any' for XmlAnyElementAttribute.
                    throw new InvalidOperationException(SR.Format(SR.XmlChoiceMissingAnyValue, choiceMapping.TypeDesc!.FullName));
                }
                // Type {0} is missing value for '{1}'.
                throw new InvalidOperationException(SR.Format(SR.XmlChoiceMissingValue, choiceMapping.TypeDesc!.FullName, $"{element.Namespace}:{element.Name}", element.Name, element.Namespace));
            }
            CodeIdentifier.CheckValidIdentifier(enumValue);
            return enumValue;
        }
    }

    internal sealed class ReflectionAwareILGen
    {
        // reflectionVariables holds mapping between a reflection entity
        // referenced in the generated code (such as TypeInfo,
        // FieldInfo) and the variable which represent the entity (and
        // initialized before).
        // The types of reflection entity and corresponding key is
        // given below.
        // ----------------------------------------------------------------------------------
        // Entity           Key
        // ----------------------------------------------------------------------------------
        // Assembly         assembly.FullName
        // Type             CodeIdentifier.EscapedKeywords(type.FullName)
        // Field            fieldName+":"+CodeIdentifier.EscapedKeywords(containingType.FullName>)
        // Property         propertyName+":"+CodeIdentifier.EscapedKeywords(containingType.FullName)
        // ArrayAccessor    "0:"+CodeIdentifier.EscapedKeywords(typeof(Array).FullName)
        // MyCollectionAccessor     "0:"+CodeIdentifier.EscapedKeywords(typeof(MyCollection).FullName)
        // ----------------------------------------------------------------------------------
        internal ReflectionAwareILGen() { }

        [RequiresUnreferencedCode("calls GetTypeDesc")]
        internal static void WriteReflectionInit(TypeScope scope)
        {
            foreach (Type type in scope.Types)
            {
                scope.GetTypeDesc(type);
            }
        }

        internal static void ILGenForEnumLongValue(CodeGenerator ilg, string variable)
        {
            ArgBuilder argV = ilg.GetArg(variable);
            ilg.Ldarg(argV);
            ilg.ConvertValue(argV.ArgType, typeof(long));
        }

        internal static string GetStringForTypeof(string typeFullName)
        {
            return $"typeof({typeFullName})";
        }
        internal static string GetStringForMember(string obj, string memberName)
        {
            return $"{obj}.@{memberName}";
        }
        internal static SourceInfo GetSourceForMember(string obj, MemberMapping member, CodeGenerator ilg)
        {
            return GetSourceForMember(obj, member, member.MemberInfo, ilg);
        }
        internal static SourceInfo GetSourceForMember(string obj, MemberMapping member, MemberInfo? memberInfo, CodeGenerator ilg)
        {
            return new SourceInfo(GetStringForMember(obj, member.Name), obj, memberInfo, member.TypeDesc!.Type, ilg);
        }

        internal static void ILGenForEnumMember(CodeGenerator ilg, Type type, string memberName)
        {
            ilg.Ldc(Enum.Parse(type, memberName, false));
        }
        internal static string GetStringForArrayMember(string? arrayName, string subscript)
        {
            return $"{arrayName}[{subscript}]";
        }
        internal static string GetStringForMethod(string obj, string memberName)
        {
            return $"{obj}.{memberName}(";
        }

        [RequiresUnreferencedCode("calls ILGenForCreateInstance")]
        internal static void ILGenForCreateInstance(CodeGenerator ilg, Type type, bool ctorInaccessible, bool cast)
        {
            if (!ctorInaccessible)
            {
                ConstructorInfo ctor = type.GetConstructor(
                       CodeGenerator.InstanceBindingFlags,
                       Type.EmptyTypes
                       )!;
                if (ctor != null)
                    ilg.New(ctor);
                else
                {
                    Debug.Assert(type.IsValueType);
                    LocalBuilder tmpLoc = ilg.GetTempLocal(type);
                    ilg.Ldloca(tmpLoc);
                    ilg.InitObj(type);
                    ilg.Ldloc(tmpLoc);
                }
                return;
            }
            ILGenForCreateInstance(ilg, type, cast ? type : null);
        }

        [RequiresUnreferencedCode("calls GetType")]
        internal static void ILGenForCreateInstance(CodeGenerator ilg, Type type, Type? cast)
        {
            // Special case DBNull
            if (type == typeof(DBNull))
            {
                FieldInfo DBNull_Value = type.GetField("Value", CodeGenerator.StaticBindingFlags)!;
                ilg.LoadMember(DBNull_Value);
                return;
            }

            // Special case XElement
            // codegen the same as 'internal XElement : this("default") { }'
            if (type.FullName == "System.Xml.Linq.XElement")
            {
                Type? xName = type.Assembly.GetType("System.Xml.Linq.XName");
                if (xName != null)
                {
                    MethodInfo XName_op_Implicit = xName.GetMethod(
                        "op_Implicit",
                        CodeGenerator.StaticBindingFlags,
                        new Type[] { typeof(string) }
                        )!;
                    ConstructorInfo XElement_ctor = type.GetConstructor(
                        CodeGenerator.InstanceBindingFlags,
                        new Type[] { xName }
                        )!;
                    if (XName_op_Implicit != null && XElement_ctor != null)
                    {
                        ilg.Ldstr("default");
                        ilg.Call(XName_op_Implicit);
                        ilg.New(XElement_ctor);
                        return;
                    }
                }
            }

            Label labelReturn = ilg.DefineLabel();
            Label labelEndIf = ilg.DefineLabel();

            // TypeInfo typeInfo = type.GetTypeInfo();
            // typeInfo not declared explicitly
            ilg.Ldc(type);
            MethodInfo getTypeInfoMehod = typeof(IntrospectionExtensions).GetMethod(
                  "GetTypeInfo",
                  CodeGenerator.StaticBindingFlags,
                  new[] { typeof(Type) }
                  )!;
            ilg.Call(getTypeInfoMehod);

            // IEnumerator<ConstructorInfo> e = typeInfo.DeclaredConstructors.GetEnumerator();
            LocalBuilder enumerator = ilg.DeclareLocal(typeof(IEnumerator<>).MakeGenericType(typeof(ConstructorInfo)), "e");
            MethodInfo getDeclaredConstructors = typeof(TypeInfo).GetMethod("get_DeclaredConstructors")!;
            MethodInfo getEnumerator = typeof(IEnumerable<>).MakeGenericType(typeof(ConstructorInfo)).GetMethod("GetEnumerator")!;
            ilg.Call(getDeclaredConstructors);
            ilg.Call(getEnumerator);
            ilg.Stloc(enumerator);

            ilg.WhileBegin();
            // ConstructorInfo constructorInfo = e.Current();
            MethodInfo enumeratorCurrent = typeof(IEnumerator).GetMethod("get_Current")!;
            ilg.Ldloc(enumerator);
            ilg.Call(enumeratorCurrent);
            LocalBuilder constructorInfo = ilg.DeclareLocal(typeof(ConstructorInfo), "constructorInfo");
            ilg.Stloc(constructorInfo);

            // if (!constructorInfo.IsStatic && constructorInfo.GetParameters.Length() == 0)
            ilg.Ldloc(constructorInfo);
            MethodInfo constructorIsStatic = typeof(ConstructorInfo).GetMethod("get_IsStatic")!;
            ilg.Call(constructorIsStatic);
            ilg.Brtrue(labelEndIf);
            ilg.Ldloc(constructorInfo);
            MethodInfo constructorGetParameters = typeof(ConstructorInfo).GetMethod("GetParameters")!;
            ilg.Call(constructorGetParameters);
            ilg.Ldlen();
            ilg.Ldc(0);
            ilg.Cne();
            ilg.Brtrue(labelEndIf);

            // constructorInfo.Invoke(null);
            MethodInfo constructorInvoke = typeof(ConstructorInfo).GetMethod("Invoke", new Type[] { typeof(object[]) })!;
            ilg.Ldloc(constructorInfo);
            ilg.Load(null);
            ilg.Call(constructorInvoke);
            ilg.Br(labelReturn);

            ilg.MarkLabel(labelEndIf);
            ilg.WhileBeginCondition(); // while (e.MoveNext())
            MethodInfo IEnumeratorMoveNext = typeof(IEnumerator).GetMethod(
                "MoveNext",
                CodeGenerator.InstanceBindingFlags,
                Type.EmptyTypes)!;
            ilg.Ldloc(enumerator);
            ilg.Call(IEnumeratorMoveNext);
            ilg.WhileEndCondition();
            ilg.WhileEnd();

            MethodInfo Activator_CreateInstance = typeof(Activator).GetMethod(
                  "CreateInstance",
                  CodeGenerator.StaticBindingFlags,
                  new Type[] { typeof(Type) }
                  )!;
            ilg.Ldc(type);
            ilg.Call(Activator_CreateInstance);
            ilg.MarkLabel(labelReturn);
            if (cast != null)
                ilg.ConvertValue(Activator_CreateInstance.ReturnType, cast);
        }

        [RequiresUnreferencedCode("calls LoadMember")]
        internal static void WriteLocalDecl(string variableName, SourceInfo initValue)
        {
            Type localType = initValue.Type!;
            LocalBuilder localA = initValue.ILG.DeclareOrGetLocal(localType, variableName);
            if (initValue.Source != null)
            {
                if (initValue == "null")
                {
                    initValue.ILG.Load(null);
                }
                else
                {
                    if (initValue.Arg.StartsWith("o.@", StringComparison.Ordinal))
                    {
                        Debug.Assert(initValue.MemberInfo != null);
                        Debug.Assert(initValue.MemberInfo.Name == initValue.Arg.Substring(3));
                        initValue.ILG.LoadMember(initValue.ILG.GetLocal("o"), initValue.MemberInfo);
                    }
                    else if (initValue.Source.EndsWith(']'))
                    {
                        initValue.Load(initValue.Type);
                    }
                    else if (initValue.Source == "fixup.Source" || initValue.Source == "e.Current")
                    {
                        string[] vars = initValue.Source.Split('.');
                        object fixup = initValue.ILG.GetVariable(vars[0]);
                        PropertyInfo propInfo = CodeGenerator.GetVariableType(fixup).GetProperty(vars[1])!;
                        initValue.ILG.LoadMember(fixup, propInfo);
                        initValue.ILG.ConvertValue(propInfo.PropertyType, localA.LocalType);
                    }
                    else
                    {
                        object sVar = initValue.ILG.GetVariable(initValue.Arg);
                        initValue.ILG.Load(sVar);
                        initValue.ILG.ConvertValue(CodeGenerator.GetVariableType(sVar), localA.LocalType);
                    }
                }
                initValue.ILG.Stloc(localA);
            }
        }

        [RequiresUnreferencedCode("calls ILGenForCreateInstance")]
        internal static void WriteCreateInstance(string source, bool ctorInaccessible, Type type, CodeGenerator ilg)
        {
            LocalBuilder sLoc = ilg.DeclareOrGetLocal(type, source);
            ILGenForCreateInstance(ilg, type, ctorInaccessible, ctorInaccessible);
            ilg.Stloc(sLoc);
        }

        [RequiresUnreferencedCode("calls Load")]
        internal static void WriteInstanceOf(SourceInfo source, Type type, CodeGenerator ilg)
        {
            source.Load(typeof(object));
            ilg.IsInst(type);
            ilg.Load(null);
            ilg.Cne();
        }

        [RequiresUnreferencedCode("calls Load")]
        [RequiresDynamicCode(XmlSerializer.AotSerializationWarning)]
        internal static void WriteArrayLocalDecl(string typeName, string variableName, SourceInfo initValue, TypeDesc arrayTypeDesc)
        {
            Debug.Assert(typeName == arrayTypeDesc.CSharpName || typeName == $"{arrayTypeDesc.CSharpName}[]");
            Type localType = (typeName == arrayTypeDesc.CSharpName) ? arrayTypeDesc.Type! : arrayTypeDesc.Type!.MakeArrayType();
            // This may need reused variable to get code compat?
            LocalBuilder local = initValue.ILG.DeclareOrGetLocal(localType, variableName);
            initValue.Load(local.LocalType);
            initValue.ILG.Stloc(local);
        }
        internal static void WriteTypeCompare(string variable, Type type, CodeGenerator ilg)
        {
            Debug.Assert(type != null);
            Debug.Assert(ilg != null);
            ilg.Ldloc(typeof(Type), variable);
            ilg.Ldc(type);
            ilg.Ceq();
        }
        internal static void WriteArrayTypeCompare(string variable, Type arrayType, CodeGenerator ilg)
        {
            Debug.Assert(arrayType != null);
            Debug.Assert(ilg != null);
            ilg.Ldloc(typeof(Type), variable);
            ilg.Ldc(arrayType);
            ilg.Ceq();
        }

        [return: NotNullIfNotNull(nameof(value))]
        internal static string? GetQuotedCSharpString(string? value) =>
            value is null ? null :
            $"@\"{GetCSharpString(value)}\"";

        [return: NotNullIfNotNull(nameof(value))]
        internal static string? GetCSharpString(string? value)
        {
            if (value == null)
            {
                return null;
            }

            // Find the first character to be escaped.
            int i;
            for (i = 0; i < value.Length; i++)
            {
                if (value[i] is < (char)32 or '\"')
                {
                    break;
                }
            }

            // If nothing needs to be escaped, return the original string.
            if (i == value.Length)
            {
                return value;
            }

            var builder = new ValueStringBuilder(stackalloc char[128]);

            // Copy over all text that needn't be escaped.
            builder.Append(value.AsSpan(0, i));

            // Process the remainder of the string, escaping each value that needs to be.
            for (; i < value.Length; i++)
            {
                char ch = value[i];

                if (ch < 32)
                {
                    if (ch == '\r')
                    {
                        builder.Append("\\r");
                    }
                    else if (ch == '\n')
                    {
                        builder.Append("\\n");
                    }
                    else if (ch == '\t')
                    {
                        builder.Append("\\t");
                    }
                    else
                    {
                        byte b = (byte)ch;
                        builder.Append("\\x");
                        builder.Append(HexConverter.ToCharUpper(b >> 4));
                        builder.Append(HexConverter.ToCharUpper(b));
                    }
                }
                else if (ch == '\"')
                {
                    builder.Append("\"\"");
                }
                else
                {
                    builder.Append(ch);
                }
            }

            return builder.ToString();
        }
    }
}
