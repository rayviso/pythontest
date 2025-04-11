import os

def rename_files(directory, prefix='', suffix='', replace='', replace_with=''):
    for root, dirs, files in os.walk(directory):



        for filename in files:
            new_name = filename

            if replace:
                new_name = new_name.replace(replace, replace_with)

            if prefix:
                new_name = prefix + new_name

            if suffix:
                name, ext = os.path.splitext(new_name)
                new_name = name + suffix + ext

            old_file = os.path.join(root, filename)
            new_file = os.path.join(root, new_name)

            os.rename(old_file, new_file)
            print(f'Renamed: {old_file} -> {new_file}')


def rename_dir(dirpath, prefix=""):
    for root, dirs, files in os.walk(dirpath):
        for dir in dirs:
            print(dir)
            s1 = dir.split(".")[0]
            s2 = dir.split(".")[1]
            print(s1, s2)
            os.rename(dirpath + "/" + dir, dirpath + "/" + s2)


if __name__ == '__main__':

    rename_dir(r"C:\Users\Administrator\Desktop\补材料-四组\10.交付\2.新交付\4.0403 任务交付\交付内容")