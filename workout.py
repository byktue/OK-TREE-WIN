import os
import ast
from typing import List, Dict, Tuple
import re


def get_python_functions(file_path: str) -> List[str]:
    """解析Python文件，获取所有函数名（包括类方法）"""
    functions = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=file_path)

        for node in ast.walk(tree):
            # 处理普通函数
            if isinstance(node, ast.FunctionDef):
                functions.append(node.name)
            # 处理类中的方法
            elif isinstance(node, ast.ClassDef):
                for class_node in ast.walk(node):
                    if isinstance(class_node, ast.FunctionDef):
                        functions.append(f"{node.name}.{class_node.name}")  # 类.方法格式
    except Exception as e:
        print(f"⚠️ 跳过有问题的Python文件 {file_path}: {str(e)}")
        return []

    return sorted(functions)


def get_java_structure(file_path: str) -> Tuple[List[str], List[str]]:
    """解析Java文件，获取类名和方法名"""
    classes = []
    methods = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 移除注释（单行//和多行/* */）
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

        # 匹配类定义（public class、class、abstract class、final class等）
        class_pattern = r'(?:public|private|protected|abstract|final|static)?\s+class\s+(\w+)'
        class_matches = re.findall(class_pattern, content)
        classes = sorted(list(set(class_matches)))  # 去重并排序

        # 匹配方法定义（排除接口方法和抽象方法）
        # 匹配模式：访问修饰符? 静态? 返回类型 方法名(参数) { ... }
        method_pattern = r'(?:public|private|protected|static|final|native|synchronized)?\s+' \
                        r'(?:\w+\s*<[^>]*>\s*|\w+\s*)' \
                        r'(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:,\s*\w+)*)?\s*\{'
        method_matches = re.findall(method_pattern, content)
        methods = sorted(list(set(method_matches)))  # 去重并排序

    except Exception as e:
        print(f"⚠️ 跳过有问题的Java文件 {file_path}: {str(e)}")
        return [], []

    return classes, methods


def build_directory_structure(root_dir: str) -> Dict:
    """构建目录结构，包含所有Python和Java文件及其结构"""
    structure = {
        'name': os.path.basename(root_dir),
        'type': 'directory',
        'children': []
    }

    # 获取目录下的所有条目，并按目录优先、名称排序
    try:
        entries = sorted(os.listdir(root_dir), key=lambda x: (not os.path.isdir(os.path.join(root_dir, x)), x))
    except PermissionError:
        print(f"❌ 没有权限访问目录 {root_dir}，已跳过")
        return structure

    for entry in entries:
        entry_path = os.path.join(root_dir, entry)

        # 跳过隐藏文件/目录和__pycache__
        if entry.startswith('.') or entry == '__pycache__' or entry == 'target':
            continue

        if os.path.isdir(entry_path):
            # 递归处理子目录
            subdir_struct = build_directory_structure(entry_path)
            if subdir_struct['children']:
                structure['children'].append(subdir_struct)
        else:
            # 处理Python文件
            if entry.endswith('.py'):
                functions = get_python_functions(entry_path)
                file_struct = {
                    'name': entry,
                    'type': 'file',
                    'language': 'Python',
                    'functions': functions
                }
                structure['children'].append(file_struct)
            # 处理Java文件
            elif entry.endswith('.java'):
                classes, methods = get_java_structure(entry_path)
                file_struct = {
                    'name': entry,
                    'type': 'file',
                    'language': 'Java',
                    'classes': classes,
                    'methods': methods
                }
                structure['children'].append(file_struct)

    return structure


def print_structure(structure: Dict, indent: int = 0, is_last: bool = True) -> None:
    """打印目录结构，按层级展示，包含Python函数和Java类/方法"""
    # 处理根目录
    if indent == 0:
        print(f"📂 {structure['name']}")
        indent += 1
    else:
        # 计算前缀
        prefix = '    ' * (indent - 1)
        if is_last:
            prefix += '└── '
        else:
            prefix += '├── '
        
        if structure['type'] == 'directory':
            print(f"{prefix}📂 {structure['name']}")
        else:
            # 文件类型，添加语言标识
            lang_icon = '🐍' if structure['language'] == 'Python' else '☕'
            print(f"{prefix}{lang_icon} {structure['name']}")

    # 打印文件内容
    if structure['type'] == 'file':
        if structure['language'] == 'Python' and structure['functions']:
            for i, func in enumerate(structure['functions']):
                func_is_last = i == len(structure['functions']) - 1
                func_prefix = '    ' * indent
                if func_is_last:
                    func_prefix += '└── '
                else:
                    func_prefix += '├── '
                print(f"{func_prefix}🔧 {func}()")
        
        elif structure['language'] == 'Java':
            # 打印Java类
            for i, cls in enumerate(structure.get('classes', [])):
                cls_is_last = i == len(structure['classes']) - 1 and not structure['methods']
                cls_prefix = '    ' * indent
                if cls_is_last:
                    cls_prefix += '└── '
                else:
                    cls_prefix += '├── '
                print(f"{cls_prefix}📦 {cls}")
            
            # 打印Java方法
            for i, method in enumerate(structure.get('methods', [])):
                method_is_last = i == len(structure['methods']) - 1
                method_prefix = '    ' * indent
                if method_is_last:
                    method_prefix += '└── '
                else:
                    method_prefix += '├── '
                print(f"{method_prefix}🔧 {method}()")

    # 递归处理子节点
    if structure['type'] == 'directory' and structure['children']:
        for i, child in enumerate(structure['children']):
            child_is_last = i == len(structure['children']) - 1
            print_structure(child, indent + 1, child_is_last)


def main():
    import sys
    # 获取当前目录或命令行指定的目录
    root_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()

    if not os.path.isdir(root_dir):
        print(f"错误: {root_dir} 不是有效的目录")
        return

    print(f"项目结构及代码元素列表 (根目录: {root_dir}):\n")
    structure = build_directory_structure(root_dir)
    print_structure(structure)
    print("\n图例:")
    print("📂 目录   🐍 Python文件   ☕ Java文件   📦 Java类   🔧 方法/函数")


if __name__ == "__main__":
    main()