#!/bin/bash

FLAG_PATH=/this_is_flag
#FLAG_PATH=/home/ctf/flag
FLAG_MODE=M_ECHO
if [ ${ICQ_FLAG} ];then
    case $FLAG_MODE in
        "M_ECHO")
            echo -n ${ICQ_FLAG} > ${FLAG_PATH}
            FILE_MODE=755 # 注意这里的权限，flag的权限一定要注意，是所有用户可读，还是只有root可读
            chmod ${FILE_MODE} ${FLAG_PATH}
            ;;
        "M_SED")
            #sed -i "s/flag{x*}/${ICQ_FLAG}/" ${FLAG_PATH}
            sed -i -r "s/flag\{.*\}/${ICQ_FLAG}/" ${FLAG_PATH}
            ;;
        "M_SQL")
            # sed -i -r "s/flag\{.*\}/${ICQ_FLAG}/" ${FLAG_PATH}
            # mysql -uroot -proot < ${FLAG_PATH}
            ;;
        *)
            ;;
    esac
    echo [+] ICQ_FLAG OK
    unset ICQ_FLAG
else
    echo [!] no ICQ_FLAG
fi

#del eci env
rm -rf /etc/profile.d/pouchenv.sh
rm -rf /etc/instanceInfo