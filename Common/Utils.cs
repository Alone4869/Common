using System.Reflection;

namespace Common
{
	/// <summary>
	/// 常用工具类
	/// </summary>
	public static class Utils
	{
		/// <summary>
		/// 获取实现了某个接口的所有类型
		/// </summary>
		/// <param name="assembly"></param>
		/// <param name="interfaceType"></param>
		/// <returns></returns>
		public static List<Type> GetAllTypesImplementingInterface(Assembly assembly, Type interfaceType)
		{
			List<Type> types = new List<Type>();
			Type[] allTypes = assembly.GetTypes();

			foreach (var type in allTypes)
			{
				if (type.IsClass && !type.IsAbstract && interfaceType.IsAssignableFrom(type))
				{
					types.Add(type);
				}
			}

			return types;
		}
	}
}
