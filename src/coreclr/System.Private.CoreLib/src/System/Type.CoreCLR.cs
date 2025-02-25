// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security;
using StackCrawlMark = System.Threading.StackCrawlMark;

namespace System
{
    public abstract partial class Type : MemberInfo, IReflect
    {
        [RequiresUnreferencedCode("The type might be removed")]
        [DynamicSecurityMethod] // Methods containing StackCrawlMark local var has to be marked DynamicSecurityMethod
        public static Type? GetType(string typeName, bool throwOnError, bool ignoreCase)
        {
            StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
            return TypeNameResolver.GetType(typeName, Assembly.GetExecutingAssembly(ref stackMark),
                throwOnError: throwOnError, ignoreCase: ignoreCase);
        }

        [RequiresUnreferencedCode("The type might be removed")]
        [DynamicSecurityMethod] // Methods containing StackCrawlMark local var has to be marked DynamicSecurityMethod
        public static Type? GetType(string typeName, bool throwOnError)
        {
            StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
            return TypeNameResolver.GetType(typeName, Assembly.GetExecutingAssembly(ref stackMark),
                throwOnError: throwOnError);
        }

        [RequiresUnreferencedCode("The type might be removed")]
        [DynamicSecurityMethod] // Methods containing StackCrawlMark local var has to be marked DynamicSecurityMethod
        public static Type? GetType(string typeName)
        {
            StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
            return TypeNameResolver.GetType(typeName, Assembly.GetExecutingAssembly(ref stackMark));
        }

        [RequiresUnreferencedCode("The type might be removed")]
        [DynamicSecurityMethod] // Methods containing StackCrawlMark local var has to be marked DynamicSecurityMethod
        public static Type? GetType(
            string typeName,
            Func<AssemblyName, Assembly?>? assemblyResolver,
            Func<Assembly?, string, bool, Type?>? typeResolver)
        {
            StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
            return TypeNameResolver.GetType(typeName, assemblyResolver, typeResolver,
                ((assemblyResolver != null) && (typeResolver != null)) ? null : Assembly.GetExecutingAssembly(ref stackMark));
        }

        [RequiresUnreferencedCode("The type might be removed")]
        [DynamicSecurityMethod] // Methods containing StackCrawlMark local var has to be marked DynamicSecurityMethod
        public static Type? GetType(
            string typeName,
            Func<AssemblyName, Assembly?>? assemblyResolver,
            Func<Assembly?, string, bool, Type?>? typeResolver,
            bool throwOnError)
        {
            StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
            return TypeNameResolver.GetType(typeName, assemblyResolver, typeResolver,
                ((assemblyResolver != null) && (typeResolver != null)) ? null : Assembly.GetExecutingAssembly(ref stackMark),
                throwOnError: throwOnError);
        }

        [RequiresUnreferencedCode("The type might be removed")]
        [DynamicSecurityMethod] // Methods containing StackCrawlMark local var has to be marked DynamicSecurityMethod
        public static Type? GetType(
            string typeName,
            Func<AssemblyName, Assembly?>? assemblyResolver,
            Func<Assembly?, string, bool, Type?>? typeResolver,
            bool throwOnError,
            bool ignoreCase)
        {
            StackCrawlMark stackMark = StackCrawlMark.LookForMyCaller;
            return TypeNameResolver.GetType(typeName, assemblyResolver, typeResolver,
                ((assemblyResolver != null) && (typeResolver != null)) ? null : Assembly.GetExecutingAssembly(ref stackMark),
                throwOnError: throwOnError, ignoreCase: ignoreCase);
        }

        [Intrinsic]
        public static Type? GetTypeFromHandle(RuntimeTypeHandle handle)
            => handle.m_type;
    }
}
