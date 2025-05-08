//创建mtoken.js对象，用于调用里面接口
var token = new mToken("mTokenPlugin");
//动态添加option选项
function addOption(optionStr, selectID, flag) {
    if (flag == 1) {
        for (var i = 0; i < optionStr.length; ++i)
            selectID.options.add(new Option(optionStr[i], i));
    }
    if (flag == 2) {
        for (var i = 0; i < optionStr.length; ++i) {
            selectID.options.add(new Option(optionStr[i][1], i));
        }
    }
}
function decodeBase64ToBytes(base64String) {
    // 解码 Base64 字符串为原始字符串
    const rawString = atob(base64String);
    // 将原始字符串转换为字节数组
    const byteArray = new Uint8Array(rawString.length);
    for (var i = 0; i < rawString.length; i++) {
        byteArray[i] = rawString.charCodeAt(i);
    }
    // 返回字节数组
    return byteArray;
}
function getSelectedDeviceName() {
    var selDeviceList = document.getElementById("selDeviceList");
    var index = selDeviceList.selectedIndex;

    if (index < 0) {
        addLog("请查找Ukey！");
        return null;
    }

    return selDeviceList.options[index].text;
}
function ensureAppSelected() {
    var selDevAppName = document.getElementById("selDevAppName");
    var indexAppName = selDevAppName.selectedIndex;

    if (indexAppName < 0) {
        addLog("请【获取应用列表】并且【绑定应用实例】");
        return false;
    }

    return true;
}


var rtn = 0;
//加载插件并查找Ukey
function btnFindKey() {
    var selModelList = document.getElementById("selModelList").value;
    if (selModelList == "GM3000PCSC")
        rtn = token.SOF_LoadLibrary(token.GM3000PCSC);
    else if (selModelList == "GM3000")
        rtn = token.SOF_LoadLibrary(token.GM3000);
    else if (selModelList == "K7")
        rtn = token.SOF_LoadLibrary(token.K7);
    else if (selModelList == "TF")
        rtn = token.SOF_LoadLibrary(token.TF);
    else
        rtn = token.SOF_LoadLibrary(token.K5);
    if (rtn != 0) {
        addLog("加载插件失败，错误码:" + token.SOF_GetLastError());
        return;
    }
    var selDeviceList = document.getElementById("selDeviceList");
    selDeviceList.options.length = 0;
    var deviceName = token.SOF_EnumDevice();
    if (deviceName == null) {
        addLog("查找设备失败，错误码:" + token.SOF_GetLastError());
        return;
    }
    addOption(deviceName, selDeviceList, 1);
    addLog("查找设备成功。");
}
//定时检测设备
var bCheckTimer;
var CheckDeviceName = "";
function btnDeviceCheckTimer() {
    //将定时按钮禁用
    document.getElementById("btn_Timer").disabled = true;
    //选择指定的设备进行定时检测
    if (CheckDeviceName == "") {
        var selDeviceList = document.getElementById("selDeviceList");
        var index = selDeviceList.selectedIndex;
        if (index < 0) {
            addLog("请查找Ukey！");
            document.getElementById("btn_Timer").disabled = false;
            return;
        }

        CheckDeviceName = selDeviceList.options[index].text;
    }

    rtn = token.SOF_CheckExists(CheckDeviceName);
    if (rtn == 1) {
        addLog("检测到KEY正常插入 ID ： " + CheckDeviceName);
    }
    else {
        addLog("检测KEY存在异常，错误码：" + token.SOF_GetLastError());
        //当检测不到后，重新再查找一次UKEY
        CheckDeviceName = token.SOF_EnumDevice();
    }
    //建议3秒定时一次
    bCheckTimer = setTimeout("btnDeviceCheckTimer()", 3000);
}
//停止定时检测
function btnCancelDeviceTimer() {
    //将定时按钮启用
    document.getElementById("btn_Timer").disabled = false;
    clearTimeout(bCheckTimer);
    addLog("已停止。");
}
//获取应用列表
function btnGetDevAppList() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //应用名称
    var selDevAppName = document.getElementById("selDevAppName");
    selDevAppName.options.length = 0;

    var appName = token.SOF_GetApplicationList(deviceName);
    if (appName == null) {
        addLog("获取应用列表失败，请确认Ukey是否已经创建应用初始化，错误码：" + token.SOF_GetLastError());
        return;
    }
    addOption(appName, selDevAppName, 1);
    addLog("获取应用列表成功。");
}
//绑定应用实例
function btnDeviceInstance() {

    var selDevAppName = document.getElementById("selDevAppName");
    var indexAppName = selDevAppName.selectedIndex;
    if (indexAppName < 0) {
        addLog("请获取应用列表！");
        return;
    }
    //获取当前选中的应用
    var appName = selDevAppName.options[selDevAppName.selectedIndex].text;

    var selDeviceList = document.getElementById("selDeviceList");
    var selDeviceName = selDeviceList.options[selDeviceList.selectedIndex].text;

    //绑定当前设备ID的应用；appName直接传入 "" 代表默认绑定设备的第一个应用。
    rtn = token.SOF_GetDeviceInstance(selDeviceName, appName);
    if (rtn != 0) {
        addLog("绑定应用实例失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("绑定应用实例成功。");
}
//跨进程访问
function btnIPCRequest() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    rtn = token.SOF_SetCrossAccess("TRUE");
    if (rtn != 0) {
        addLog("跨进程访问失败,错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("跨进程访问成功。");
}
//验证Ukey的用户密码
function btnVerifyUPIN() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtUPIN = document.getElementById("txtUPIN").value;
    if (txtUPIN == "") {
        addLog("请输入Ukey的用户密码！");
        return;
    }
    rtn = token.SOF_Login(txtUPIN);
    if (rtn != 0) {
        addLog("验证失败,错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验证成功。");
}
//验证Ukey的用户密码-异或运算
function btnVerifyUPIN_Xor() {
    //获取KEY的硬件ID，作为异或算法的密钥
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    if (!ensureAppSelected()) {
        return;
    }
    //获取验证的密码，作为异或算法的值
    var txtUPIN = document.getElementById("txtUPIN").value;
    if (txtUPIN == "") {
        addLog("请输入Ukey的用户密码！");
        return;
    }
    //进行异或运算
    var verCode = xorEncrypt(deviceName, txtUPIN);
    rtn = token.SOF_VerifyCode(verCode);
    if (rtn != 0) {
        addLog("验证失败,错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验证成功。");
}
//异或计算-兼容IE
function xorEncrypt(key, value) {
    // 将字符串转换为 UTF-8 字节数组的辅助函数
    function stringToUtf8ByteArray(str) {
        var out = [], p = 0;
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 128) {
                // 对于ASCII字符，直接添加
                out[p++] = c;
            } else if (c < 2048) {
                // 对于非ASCII字符，使用UTF-8编码
                out[p++] = (c >> 6) | 192;
                out[p++] = (c & 63) | 128;
            } else if (
                (c & 0xfc00) === 0xd800 &&
                i + 1 < str.length &&
                (str.charCodeAt(i + 1) & 0xfc00) === 0xdc00
            ) {
                // 对于代理对，处理4字节编码
                c = 0x10000 + ((c & 0x03ff) << 10) + (str.charCodeAt(++i) & 0x03ff);
                out[p++] = (c >> 18) | 240;
                out[p++] = ((c >> 12) & 63) | 128;
                out[p++] = ((c >> 6) & 63) | 128;
                out[p++] = (c & 63) | 128;
            } else {
                // 对于其他字符，使用三字节编码
                out[p++] = (c >> 12) | 224;
                out[p++] = ((c >> 6) & 63) | 128;
                out[p++] = (c & 63) | 128;
            }
        }
        return out;
    }
    // 将密钥和待加密值转换为字节数组
    var keyBytes = stringToUtf8ByteArray(key);
    var valueBytes = stringToUtf8ByteArray(value.toString());
    var resultBytes = []; // 存储异或运算结果的字节数组
    // 执行异或加密
    for (var i = 0; i < valueBytes.length; i++) {
        resultBytes[i] = valueBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    // 将结果字节数组转换为字符串
    var base64Result = "";
    for (var i = 0; i < resultBytes.length; i++) {
        base64Result += String.fromCharCode(resultBytes[i]);
    }
    // 使用 Base64 编码结果字符串
    return window.btoa ? window.btoa(base64Result) : null; // 确保 btoa 可以被使用
}
//登出
function btnLogoutUPIN() {
    var txtUPIN = document.getElementById("txtUPIN").value;
    if (txtUPIN == "") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    rtn = token.SOF_LogOut();
    if (rtn != 0) {
        addLog("登出失败,错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("登出成功。");
}
//验证用户指纹
function btnVerifyFinger() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    /**
     * 先获取Ukey类型，确保Ukey为指纹Key,使用SOF_GetFingerInfo函数来做判断
     * 1.非指纹普通KEY走这个接口，那么普通KEY肯定是没有指纹模块的，那么rtn就不会等于零。
     * 2.指纹KEY走这个接口，本身就是初始化好的指纹模块KEY，走这个接口，那么rtn肯定等于0
     * */
    rtn = token.SOF_GetFingerInfo(deviceName, 1);
    if (rtn.rtn != 0) {
        addLog("Ukey不是指纹Key，无法执行验证指纹操作，错误码：" + token.SOF_GetLastError());
        return;
    }
    alert("当指纹KEY上的指示灯开始闪烁时，请按压手指以验证指纹......"); //Longmai的示例提示方式
    rtn = token.SOF_VerifyFingerprintEx(deviceName);
    //201326594的十六进制0x0C000002	//指纹不存在
    if (rtn.rtn == "201326594") {
        addLog("指纹不存在，请确认是否录入了指纹！");
        return;
    }
    if (rtn.rtn != 0) {
        addLog("验证指纹失败，错误码：" + token.SOF_GetLastError() + "，剩余重试次数：" + rtn.RetryCount);
        return;
    }
    addLog("验证指纹成功，指纹ID：" + rtn.FingerId);
}
//获取设备信息
function btnGetDeviceInfo() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var deviceInfo = document.getElementById("txtGetDeviceInfo");
    deviceInfo.value = "";
    var strInfo;
    rtn = token.SOF_GetDeviceInfo(deviceName, token.SGD_DEVICE_NAME);
    strInfo = "设备名称: " + rtn + "\r";
    rtn = token.SOF_GetDeviceInfo(deviceName, token.SGD_DEVICE_SERIAL_NUMBER);
    strInfo += "设备序列号: " + rtn + "\r";
    rtn = token.SOF_GetDeviceInfo(deviceName, token.SGD_DEVICE_SUPPORT_STORANGE_SPACE);
    strInfo += "设备总空间: " + Math.floor(rtn / 1024) + " KB\r"
    rtn = token.SOF_GetDeviceInfo(deviceName, token.SGD_DEVICE_SUPPORT_FREE_SAPCE);
    strInfo += "设备剩余空间: " + Math.floor(rtn / 1024) + " KB\r"
    rtn = token.SOF_GetDeviceInfo(deviceName, token.SGD_DEVICE_HARDWARE_VERSION);
    strInfo += "硬件版本: " + rtn + "\r";
    rtn = token.SOF_GetDeviceInfo(deviceName, token.SGD_DEVICE_MANUFACTURER);
    strInfo += "设备生产商: " + rtn + "\r";
    if (rtn == null) {
        addLog("获取设备信息失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    deviceInfo.value = strInfo;
    addLog("获取成功。");
}
//获取用户密码信息
function btnGetUPINInfo() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    rtn = token.SOF_GetPinRetryCountInfo(deviceName);
    var txt_PinInfo = document.getElementById("txtGetUPINInfo");
    var infos = "";
    var defaultPinStr = "";
    var locked = "";
    infos = "最大重试次数：" + rtn.maxRetryCount + "\n";
    infos += "当前剩余次数：" + rtn.retryCount + "\n";
    if (rtn.retryCount == 0) {
        locked = "已经锁定";
    } else if (rtn.retryCount > 0) {
        locked = "没有锁定";
    }
    infos += "用户Pin是否被锁定：" + locked + "\n";

    if (rtn.defaultPin == 1) {
        defaultPinStr = "是";
    } else if (rtn.defaultPin == 0) {
        defaultPinStr = "否";
    }
    infos += "是否为默认密码：" + defaultPinStr;
    txt_PinInfo.value = infos;
    addLog("获取成功。");
}
//获取插件版本号
function btnGetVersion() {
    //先加载插件，再获取版本
    var selModelList = document.getElementById("selModelList").value;
    if (selModelList == "GM3000PCSC")
        rtn = token.SOF_LoadLibrary(token.GM3000PCSC);
    else if (selModelList == "GM3000")
        rtn = token.SOF_LoadLibrary(token.GM3000);
    else if (selModelList == "K7")
        rtn = token.SOF_LoadLibrary(token.K7);
    else if (selModelList == "TF")
        rtn = token.SOF_LoadLibrary(token.TF);
    else
        rtn = token.SOF_LoadLibrary(token.K5);
    if (rtn != 0) {
        addLog("加载插件失败，错误码:" + token.SOF_GetLastError());
        return;
    }
    rtn = token.SOF_GetVersion();
    if (rtn == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var txtGetVersion = document.getElementById("txtGetVersion");
    txtGetVersion.value = rtn;
    addLog("获取成功。");
}
//获取随机数
function btnGetRandom() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    rtn = token.SOF_GenerateRandom(deviceName, 16);
    if (rtn == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var txtGetRandom = document.getElementById("txtGetRandom");
    txtGetRandom.value = rtn;
    addLog("获取成功。");

}
//设置设备名称
function btnSetDeviceName() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var txtSetDeviceName = document.getElementById("txtSetDeviceName").value;
    if (txtSetDeviceName == "") {
        addLog("请输入需要设置的设备名称！");
        return;
    }
    rtn = token.SOF_SetLabel(deviceName, txtSetDeviceName);
    if (rtn != 0) {
        addLog("设置失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("设置成功。");
}
//认证设备密钥
function btnAuthDevCode() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var txtAuthDevCode = document.getElementById("txtAuthDevCode").value;
    if (txtAuthDevCode == "") {
        addLog("请输入设备密钥！");
        return;
    }
    rtn = token.SOF_DevAuth(deviceName, txtAuthDevCode);
    if (rtn != 0) {
        addLog("认证失败，剩余认证次数：" + token.SOF_GetLastError());
        return;
    }
    addLog("认证成功。");
}
//修改设备密钥
function btnChangeAuthDevCode() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var txtChangeAuthDevCode = document.getElementById("txtChangeAuthDevCode").value;
    if (txtChangeAuthDevCode == "") {
        addLog("请输入需要修改的设备密钥！");
        return;
    }
    rtn = token.SOF_ChangeDevAuthKey(deviceName, txtChangeAuthDevCode);
    if (rtn == "167772205") {
        addLog("请认证设备密钥，认证成功后再修改！");
        return;
    }
    if (rtn != 0) {
        addLog("修改失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("修改成功。");
}
//获取应用列表
function btnGetAppList() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //应用名称
    var selAppList = document.getElementById("selAppList");
    selAppList.options.length = 0;

    var appName = token.SOF_GetApplicationList(deviceName);
    if (appName == null) {
        addLog("获取应用列表失败，请确认Ukey是否已经创建应用初始化，错误码：" + token.SOF_GetLastError());
        return;
    }
    addOption(appName, selAppList, 1);
    addLog("获取应用列表成功。");
}
//删除应用
function btnDelApp() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var selAppList = document.getElementById("selAppList");
    var indexAppName = selAppList.selectedIndex;
    if (indexAppName < 0) {
        addLog("请获取应用！");
        return;
    }
    //获取当前选中的应用
    var appName = selAppList.options[selAppList.selectedIndex].text;
    rtn = token.SOF_DeleteApplication(deviceName, appName);
    if (rtn == "167772205") {
        addLog("请认证设备密钥！");
        return;
    }
    if (rtn != 0) {
        addLog("删除失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("删除成功。");
}
//创建应用
function btnCreateApp() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //应用名称
    var txtNameApp = document.getElementById("txtNameApp").value;
    //管理员密码
    var txtAdminPWDApp = document.getElementById("txtAdminPWDApp").value;
    //管理员密码最大重试次数
    var txtAdminPWDMaxCountApp = document.getElementById("txtAdminPWDMaxCountApp").value;
    //用户密码
    var txtUserPWDApp = document.getElementById("txtUserPWDApp").value;
    //用户密码最大重试次数
    var txtUserPWDMaxCountApp = document.getElementById("txtUserPWDMaxCountApp").value;
    //在该应用下创建文件和容器的权限
    var selSecureParm = document.getElementById("selSecureParm").value;
    rtn = token.SOF_CreateApplication(deviceName, txtNameApp, txtAdminPWDApp, txtAdminPWDMaxCountApp, txtUserPWDApp, txtUserPWDMaxCountApp, selSecureParm);
    if (rtn == "167772205") {
        addLog("请认证设备密钥！");
        return;
    }
    if (rtn != 0) {
        addLog("创建失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("创建成功。");
}
//验证管理员密码
function btnVerifySOPIN() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtSOPIN = document.getElementById("txtSOPIN").value;
    if (txtSOPIN == "") {
        addLog("请输入管理员密码！");
        return;
    }
    rtn = token.SOF_LoginSoPin(txtSOPIN);
    if (rtn != 0) {
        addLog("验证失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验证成功。");
}
//修改Ukey的用户密码
function btnChangeUPIN() {
    if (!ensureAppSelected()) {
        return;
    }
    //原用户密码
    var txtUPIN_Old = document.getElementById("txtUPIN_Old").value;
    if (txtUPIN_Old == "") {
        addLog("请输入原用户密码！");
        return;
    }
    //新用户密码
    var txtUPIN_New = document.getElementById("txtUPIN_New").value;
    if (txtUPIN_New == "") {
        addLog("请输入新用户密码！");
        return;
    }
    rtn = token.SOF_ChangePassWd(txtUPIN_Old, txtUPIN_New);
    if (rtn != 0) {
        addLog("修改失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("修改成功。");
}
//修改Ukey管理员密码
function btnChangeSOPIN() {
    if (!ensureAppSelected()) {
        return;
    }
    //原管理员密码
    var txtSOPIN_Old = document.getElementById("txtSOPIN_Old").value;
    if (txtSOPIN_Old == "") {
        addLog("请输入原管理员密码！");
        return;
    }
    //新管理员密码
    var txtSOPIN_New = document.getElementById("txtSOPIN_New").value;
    if (txtSOPIN_New == "") {
        addLog("请输入新管理员密码！");
        return;
    }
    rtn = token.SOF_ChangeSoPin(txtSOPIN_Old, txtSOPIN_New);
    if (rtn != 0) {
        addLog("修改失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("修改成功。");
}
//解锁Ukey用户密码
function btnUnLockUPIN() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtSOPIN_UnLock = document.getElementById("txtSOPIN_UnLock").value;
    if (txtSOPIN_UnLock == "") {
        addLog("请输入管理员密码！");
        return;
    }
    var txtUPIN_UnLock = document.getElementById("txtUPIN_UnLock").value;
    if (txtUPIN_UnLock == "") {
        addLog("请输入用户密码！");
        return;
    }
    rtn = token.SOF_UnblockUserPin(txtSOPIN_UnLock, txtUPIN_UnLock);
    if (rtn != 0) {
        addLog("解锁失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("解锁成功。");
}
//生成解锁请求码
function btnRequestCode() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var txtRequestCode = document.getElementById("txtRequestCode");
    var request = token.SOF_GenRemoteUnblockRequest(deviceName);
    if (request == null) {
        addLog("生成失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    txtRequestCode.value = request;
    addLog("生成成功。");
}
//生成解锁响应码
function btnResponseCode() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var txtRequestCode = document.getElementById("txtRequestCode").value;
    if (txtRequestCode == "") {
        addLog("请生成解锁请求码！");
        return;
    }
    //申请解锁方的管理员密码
    var txtResponseCode_SOPIN = document.getElementById("txtResponseCode_SOPIN").value;
    if (txtResponseCode_SOPIN == "") {
        addLog("请输入申请解锁方的管理员密码！");
        return;
    }
    //需要解锁的用户密码
    var txtResponseCode_UPIN = document.getElementById("txtResponseCode_UPIN").value;
    if (txtResponseCode_UPIN == "") {
        addLog("请输入需要解锁的用户密码！");
        return;
    }
    rtn = token.SOF_GenResetpwdResponse(deviceName, txtRequestCode, txtResponseCode_SOPIN, txtResponseCode_UPIN);
    if (rtn == null) {
        addLog("生成失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var txtResponseCode = document.getElementById("txtResponseCode");
    txtResponseCode.value = rtn;
}
//解锁
function btnRemoteUnlock() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //拿到解锁响应码
    var txtResponseCode = document.getElementById("txtResponseCode").value;
    if (txtResponseCode == "") {
        addLog("请生成响应码！");
        return;
    }
    rtn = token.SOF_RemoteUnblockPIN(deviceName, txtResponseCode);
    if (rtn != 0) {
        addLog("解锁失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("解锁成功！");
}
//获取用户指纹信息
function btnGetFingerInfo_User() {
    var deviceName = getSelectedDeviceName(); // 获取选中的设备名称
    if (deviceName == null) {
        return; // 若设备名称为空则直接返回
    }
    var ret = token.SOF_GetFingerInfo(deviceName, 1); // 获取指纹信息
    if (ret.rtn != 0) {
        addLog("获取指纹失败，错误码：" + token.SOF_GetLastError()); // 若返回不为0，则记录错误信息
        return;
    }
    var fingerBytes = decodeBase64ToBytes(ret.fingerIDs); // 解码指纹ID为字节数组
    var fingerInfo = ""; // 初始化指纹信息字符串
    // 拼接指纹信息
    fingerInfo += "是否允许使用：" + ret.enableFlag + "\r";
    fingerInfo += "验证级别：" + ret.verifyLevel + "\r";
    fingerInfo += "最大重试次数：" + ret.maxRetryTimes + "\r";
    fingerInfo += "剩余重试次数：" + ret.leftRetryTimes + "\r";
    fingerInfo += "指纹ID个数：" + ret.idNum + "\r";
    fingerInfo += "指纹ID列表如下：\r";
    // 使用常规的 for 循环替代 forEach 
    for (var index = 0; index < fingerBytes.length; index++) {
        fingerInfo += (index + 1) + ".(1是已录入，0是未录入) " + fingerBytes[index] + "\r";
    }
    // 将结果显示在文本框中
    document.getElementById("txtGetFingerInfo_User").value = fingerInfo;
}

//用户指纹录入
function btnFinger_Enroll() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var fingerID = document.getElementById("txtFinger_Enroll").value;
    if (fingerID == "") {
        addLog("请输入需要录入的指纹ID！");
        return;
    }
    var ret = token.SOF_GetFingerInfo(deviceName, 1);
    if (ret.rtn != 0) {
        addLog("获取指纹失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var fingerBytes = decodeBase64ToBytes(ret.fingerIDs);
    if (fingerBytes[fingerID - 1] == 1) {
        addLog("该指纹ID已经被录入，请重新输入其他指纹ID！");
        return;
    }
    if (fingerID < 1 || fingerID > fingerBytes.length) {
        addLog("输入指纹范围无效，请重新输入！");
        return;
    }

    alert("当指纹KEY上的指示灯开始闪烁时，请按压手指三次进行录入指纹......");
    rtn = token.SOF_EnrollFinger(deviceName, 1, fingerID);
    if (rtn == "167772205") {
        addLog("请验证用户密码！");
        return;
    }
    if (rtn == "201326593") {
        addLog("指纹已存在，同样的指纹不能录入两次!");
        return;
    }
    if (rtn <= 0) {
        addLog("录入指纹失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("录入成功，指纹ID：" + rtn);
}
//指纹删除
function btnFinger_Del() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var fingerID = document.getElementById("txtFinger_Enroll").value;
    if (fingerID == "") {
        addLog("请输入需要删除的指纹ID！");
        return;
    }
    var ret = token.SOF_GetFingerInfo(deviceName, 1);
    if (ret.rtn != 0) {
        addLog("获取指纹失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var fingerBytes = decodeBase64ToBytes(ret.fingerIDs);
    if (fingerBytes[fingerID - 1] == 0) {
        addLog("该指纹ID并未录入，请重新输入其他指纹ID！");
        return;
    }
    if (fingerID < 1 || fingerID > fingerBytes.length) {
        addLog("输入指纹范围无效，请重新输入！");
        return;
    }
    rtn = token.SOF_DeleteFinger(deviceName, 1, fingerID);
    if (rtn == "167772205") {
        addLog("请验证用户密码！");
        return;
    }
    if (rtn != 0) {
        addLog("删除指纹失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("删除成功。");
}
//创建容器
function btnCreateCon() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtCreateCon = document.getElementById("txtCreateCon").value;
    if (txtCreateCon == "") {
        addLog("请输入需要创建的容器名！");
        return;
    }
    rtn = token.SOF_CreateContainer(txtCreateCon);
    if (rtn == "167772205") {
        addLog("请验证用户密码！");
        return;
    }
    if (rtn == "184549430") {
        addLog("【" + txtCreateCon + "】该容器已存在，无法创建！");
        return;
    }
    if (rtn != 0) {
        addLog("创建失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("创建成功。");
}
//获取所有容器
function btnGetConList() {
    if (!ensureAppSelected()) {
        return;
    }
    var conNameList = token.SOF_EnumCertContiner();
    if (conNameList == "") {
        addLog("未找到任何容器！");
        return;
    }
    if (conNameList == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var contentList = document.getElementById("contentList");
    contentList.options.length = 0;
    addOption(conNameList, contentList, 1);
    addLog("获取成功。");
}
//导出容器中指定的数字证书
function btnExportCer() {
    var contentList = document.getElementById("contentList");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //获取导出证书的类型
    var cerType = document.getElementById("cerType").value;
    var cert = token.SOF_ExportUserCert(conName, cerType);
    if (token.SOF_GetLastError() == "a00001c") {
        addLog("未发现证书！");
        return;
    }
    if (cert == null) {
        addLog("导出失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var txtExportCer = document.getElementById("txtExportCer");
    txtExportCer.value = cert;
    addLog("导出成功。");
}
//获取证书信息
function btnGetCerInfo() {
    var txtExportCer = document.getElementById("txtExportCer").value;
    if (txtExportCer == "") {
        addLog("请导出证书！");
        return;
    }
    var txtGetCerInfo = document.getElementById("txtGetCerInfo");
    txtGetCerInfo.value = "";
    var cerInfo = "";
    var str;
    str = token.SOF_GetCertInfoByOid(txtExportCer, "2.5.29.14");
    cerInfo += "颁发者: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_ISSUER_CN);
    cerInfo += "颁发者: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_SUBJECT);
    cerInfo += "主题: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_SUBJECT_CN);
    cerInfo += "主题_CN: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_SUBJECT_EMALL);
    cerInfo += "主题_电子邮件: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_SERIAL);
    cerInfo += "序列号: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_CRL);
    cerInfo += "CRL分发点: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_NOT_BEFORE);
    cerInfo += "有效期始于: " + str + "\r";
    str = token.SOF_GetCertInfo(txtExportCer, token.SGD_CERT_VALID_TIME);
    cerInfo += "有效期至: " + str + "\r";
    if (str == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("获取成功。");
    txtGetCerInfo.value = cerInfo;
}
//根据证书序列号查询所存在的容器
function btnGetConName_CertID() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtCertID = document.getElementById("txtCertID").value;
    if (txtCertID == "") {
        addLog("请输入需要查询的证书序列号！");
        return;
    }
    var certID = token.SOF_FindContainer(txtCertID);
    if (token.SOF_GetLastError() == "a00001c" || certID == "") {
        addLog("未发现证书！");
        return;
    }
    if (certID == null) {
        addLog("查询失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    document.getElementById("txtCertConByID").value = certID;
    addLog("查询成功。");
}
//根据证书序列号删除所存在的容器
function btnDelCon_CertID() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtCertID = document.getElementById("txtCertID").value;
    if (txtCertID == "") {
        addLog("请输入需要删除的证书序列号！");
        return;
    }
    var certID = token.SOF_DeleteContainer(txtCertID);
    if (token.SOF_GetLastError() == "a00001c" || certID == "") {
        addLog("未发现证书！");
        return;
    }
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (certID == null) {
        addLog("删除失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    document.getElementById("txtCertConByID").value = "删除证书的容器为：" + certID;
    addLog("删除成功。");
}
//根据证书序列号删除cer证书
function btnDelCer_CertID() {
    if (!ensureAppSelected()) {
        return;
    }
    var txtCertID = document.getElementById("txtCertID").value;
    if (txtCertID == "") {
        addLog("请输入需要删除的证书序列号！");
        return;
    }
    var certID = token.SOF_DeleteCert(txtCertID);
    if (token.SOF_GetLastError() == "a00001c" || certID == "") {
        addLog("未发现证书！");
        return;
    }
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (certID == null) {
        addLog("删除失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    document.getElementById("txtCertConByID").value = "删除证书的容器为：" + certID;
    addLog("删除成功。");
}
//在容器内单独生成签名密钥对
function btnCreateAsym() {

    var contentList = document.getElementById("contentList");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    if (document.getElementById("txtUPIN").value == "") {
        addLog("请验证Ukey的用户密码");
        return;
    }
    var keySpec = 1;//1 为签名类型
    //非对称算法
    var asymAlg = document.getElementById("selAsym").value;
    var algorithmValue; // 定义一个变量用于存储算法的值
    // 根据选择的值定义变量
    if (asymAlg === "256") {
        algorithmValue = "131328"; // SM2
    } else if (asymAlg === "1024" || asymAlg === "2048") {
        algorithmValue = "65536"; // RSA (1024 和 2048 都使用这个值)
    }
    rtn = token.SOF_CreateKeyPair(conName, keySpec, algorithmValue, Number(asymAlg));
    if (rtn != 0) {
        addLog("生成失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("生成成功。");
}
//生成P10请求
function btnP10Request() {

    //获取容器名称
    var contentList = document.getElementById("contentList");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //先验证Ukey的用户密码
    var txtUPIN = document.getElementById("txtUPIN").value;
    if (txtUPIN == "") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    //拿到请求证书DN项
    var txtCerDN = document.getElementById("txtCerDN").value;
    if (txtCerDN == "") {
        addLog("请输入请求证书的DN项！");
        return;
    }
    //拿到非对称算法
    var asyAlgorithmType = document.getElementById("asyAlgorithmType").value;
    //拿到非对称算法的密钥长度
    var asyAlgorithmType_Len = document.getElementById("asyAlgorithmType_Len").value;
    //密钥类型
    var keySpec = 1;//必须为1 

    var p10Data = token.SOF_GenerateP10Request(conName, txtCerDN, asyAlgorithmType, keySpec, asyAlgorithmType_Len);
    if (p10Data == null) {
        addLog("生成失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    document.getElementById("txtP10Data").value = p10Data;
    addLog("生成成功。");
}
//导入签名证书
function btnImportSignCer() {
    //获取容器名称
    var contentList = document.getElementById("contentList");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //签名证书数据
    var txtSignCer = document.getElementById("txtSignCer").value;
    if (txtSignCer == "") {
        addLog("请输入签名证书数据！");
        return;
    }
    //密钥类型 1代表签名类型
    var keySpec = 1;
    rtn = token.SOF_ImportCert(conName, txtSignCer, keySpec);
    if (rtn != 0) {
        addLog("导入失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("导入成功。");
}
//导入加密证书和加密私钥数据
function btnImprotEnCer() {
    //获取容器名称
    var contentList = document.getElementById("contentList");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var container = contentList.options[indexConList].text;
    //非对称算法类型
    var nAsymAlg = document.getElementById("asyAlgorithmType").value;
    //公钥加密会话密钥数据,导入RSA证书时需要用到，SM2传入""
    var EncryptedSessionKeyData = document.getElementById("txtSessionKey").value;
    //如果导入的是RSA算法，则需要输入SessionKey数据
    if (nAsymAlg == "65536" && EncryptedSessionKeyData == "") {
        addLog("请输入 SessionKey 数据！");
        return;
    }
    //加密密钥数据，如果是SM2，则直接传入符合0016-2012的密钥对保护结构
    var EncryptedPrivateKeyData = document.getElementById("txt_PrivateKeyData_En").value;
    if (EncryptedPrivateKeyData == "") {
        addLog("请输入加密密钥数据！");
        return;
    }
    //拿到加密证书数据
    var cert = document.getElementById("txt_EncryptedCer").value;
    if (cert == "") {
        addLog("请输入加密证书数据！");
        return;
    }
    //加密私钥时用的对称算法
    var symAlg = document.getElementById("SyAlgorithmType_Import").value;
    //工作模式， 根据不同CA而定，一般传入 "" 即可
    var mode = "";
    rtn = token.SOF_ImportCryptoCertAndKey(container, cert, nAsymAlg, EncryptedSessionKeyData, symAlg, EncryptedPrivateKeyData, mode);
    if (rtn != 0) {
        addLog("导入失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("导入成功。");
}
//签名-获取容器列表
function btnGetConList_Sign() {
    if (!ensureAppSelected()) {
        return;
    }
    var conNameList = token.SOF_EnumCertContiner();
    if (conNameList == "") {
        addLog("未找到任何容器！");
        return;
    }
    if (conNameList == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var contentList = document.getElementById("contentList_Sign");
    contentList.options.length = 0;
    addOption(conNameList, contentList, 1);
    addLog("获取成功。");
}
//签名-导出容器内的指定证书
function btnExportCer_Sign() {
    var contentList = document.getElementById("contentList_Sign");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //获取导出证书的类型
    var cerType = document.getElementById("cerType_Sign").value;
    var cert = token.SOF_ExportUserCert(conName, cerType);
    if (cert == null) {
        addLog("导出失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var txtExportCer = document.getElementById("txtExportCerData");
    txtExportCer.value = cert;
    addLog("导出成功。");
}

// 获取所有容器下的CN值和容器名，当一个容器下有签名和加密证书双证时，此时获取的是签名类型的证书；当一个容器下只有一个证书，则直接获取
function btnGetUserList() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
	var getUserList = document.getElementById("getUserList_Sign");
    getUserList.options.length = 0; // 清空下拉框
    var userList = token.SOF_GetUserList(deviceName);
    if (userList == null || userList=="") {
        addLog("获取失败!");
		getUserList.options.length = 0; // 清空下拉框
        return;
    }
    

    for (var i = 0; i < userList.length; i++) {
        var cn = userList[i][0]; // CN 值
        var container = userList[i][1]; // 容器名
        var displayText = `CN: ${cn}, 容器名: ${container}`; // 格式化为 "CN: xxx, 容器名: xxx"
        var option = new Option(displayText, i); // 创建选项，text 为显示文本，value 为索引
        getUserList.options[getUserList.options.length] = option; // 添加到下拉框
    }
    addLog("获取成功。");
}
//签名-导出容器内指定的公钥数据，注意：并不是cer证书中的公钥
function btnExportPubKey() {
    var contentList = document.getElementById("contentList_Sign");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //证书类型
    var pubKeyType = document.getElementById("pubKeyType").value;
    //选择导出公钥格式，1代表0016-2012国密标准格式
    var expType = 1;
    var pubData = token.SOF_ExportPubKey(conName, pubKeyType, expType);
    if (pubData == null) {
        addLog("导出失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("导出成功。");
    document.getElementById("txtExportPubKey").value = pubData;
}
//签名
function btnSignData() {
    var contentList = document.getElementById("contentList_Sign");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //设置摘要算法
    var DigestMethod = document.getElementById("hashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);
    //密钥类型
    var ulKeySpec = 1;//1代表使用容器内的签名私钥进行签名
    //需要签名的数据原文
    var txtSignText = document.getElementById("txtSignText").value;
    if (txtSignText == "") {
        addLog("请输入需要签名的数据原文！");
        return;
    }
    //对数据原文做BASE64传给接口
    var InData = _Base64encode(txtSignText);
    //签名数据原文的长度
    var InDataLen = txtSignText.length;
    //0 预处理 1 不做预处理（当使用SM2签名时，必须用SM3摘要算法，则需要决定是否做预处理计算Z值）
    var mode = 0;
    var signedData = token.SOF_SignData(conName, ulKeySpec, InData, InDataLen, mode);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (signedData == null) {
        addLog("签名失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("签名成功。");
    document.getElementById("txtSignData").value = signedData;
}
//使用cer证书验签
function btnVerifySign() {
    //签名后的值
    var SignedValue = document.getElementById("txtSignData").value;
    if (SignedValue == "") {
        addLog("请进行签名！");
        return;
    }
    //获取Base64编码签名证书数据
    var Base64EncodeCert = document.getElementById("txtExportCerData").value;
    if (Base64EncodeCert == "") {
        addLog("请导出Ukey中的签名证书！");
        return;
    }
    //设置摘要算法
    var digestMethod = document.getElementById("hashType").value;
    var txtSignText = document.getElementById("txtSignText").value;
    if (txtSignText == "") {
        addLog("请输入签名的数据原文！");
        return;
    }
    //对数据原文做BASE64传给接口
    var InData = _Base64encode(txtSignText);

    //0 预处理 1 不做预处理（当使用SM2签名时，必须用SM3摘要算法，则需要决定是否做预处理计算Z值）
    var mode = 0;
    rtn = token.SOF_VerifySignedData(Base64EncodeCert, digestMethod, InData, SignedValue, mode);
    if (rtn != 0) {
        addLog("验签失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验签成功。");
}
//使用容器中密钥对的公钥验签
function btnVerifySign_PubKey() {
    //签名后的值
    var SignedValue = document.getElementById("txtSignData").value;
    if (SignedValue == "") {
        addLog("请进行签名！");
        return;
    }
    //公钥数据
    var pubKey = document.getElementById("txtExportPubKey").value;
    if (pubKey == "") {
        addLog("请导出容器中密钥对的签名公钥数据！");
        return;
    }
    //设置摘要算法
    var digestMethod = document.getElementById("hashType").value;

    var txtSignText = document.getElementById("txtSignText").value;
    if (txtSignText == "") {
        addLog("请输入签名的数据原文！");
        return;
    }
    //对数据原文做BASE64传给接口
    var InData = _Base64encode(txtSignText);

    rtn = token.SOF_PublicVerify(pubKey, InData, SignedValue, digestMethod);
    if (rtn != 0) {
        addLog("验签失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验签成功。");
}
//SM2签名出的数据是Der编码，此方法将解析SM2签名的R和S
function btnSignDataRS() {
    //Der签名数据
    var signData = document.getElementById("txtSignData").value;
    if (signData == "") {
        addLog("请先进行SM2签名！");
        return;
    }
    var rHex = R(signData).toUpperCase();
    document.getElementById("txtR").value = rHex;

    var sHex = S(signData).toUpperCase();
    document.getElementById("txtS").value = sHex;
}

function R(signed) {
    // 将签名后的值进行 Base64 解码
    var signedByte = atob(signed);

    // 从 ECC 签名数据结构中取出 R
    var r = new Uint8Array(32);
    var offset = (signedByte.charCodeAt(4) === 0) ? 5 : 4;
    for (var i = 0; i < 32; i++) {
        r[i] = signedByte.charCodeAt(i + offset);
    }

    // 将 Uint8Array 转换为 HEX 字符串
    var rHex = '';
    for (var i = 0; i < r.length; i++) {
        var hex = r[i].toString(16);
        rHex += hex.length === 1 ? '0' + hex : hex;
    }

    return rHex;
}

function S(signed) {
    // 将签名后的值进行 Base64 解码
    var signedByte = atob(signed);

    // 从 ECC 签名数据结构中取出 S，直接从结构最后面取 32 字节的 S 数据
    var s = new Uint8Array(32);
    for (var i = 0; i < 32; i++) {
        s[i] = signedByte.charCodeAt(signedByte.length - 32 + i);
    }

    // 将 Uint8Array 转换为 HEX 字符串
    var sHex = '';
    for (var i = 0; i < s.length; i++) {
        var hex = s[i].toString(16);
        sHex += hex.length === 1 ? '0' + hex : hex;
    }

    return sHex;
}

//签名P7
function btnSignData_P7() {
    var contentList = document.getElementById("contentList_Sign");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //设置摘要算法
    var DigestMethod = document.getElementById("hashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);
    //密钥类型
    var ulKeySpec = 1;//1代表使用容器内的签名私钥进行签名
    //需要签名的数据原文
    var txtSignText = document.getElementById("txtSignText").value;
    if (txtSignText == "") {
        addLog("请输入需要签名的数据原文！");
        return;
    }
    //对数据原文做BASE64传给接口
    var InData = _Base64encode(txtSignText);
    //是否带原文，1 不带原文 0 带原文
    var ulDetached = 0;
    var signDataP7 = token.SOF_SignDataToPKCS7(conName, ulKeySpec, InData, ulDetached);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (signDataP7 == null) {
        addLog("签名失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("签名成功。");
    document.getElementById("txtSignData").value = signDataP7;
}
//验签P7
function btnVerifySign_P7() {
    //签名后的数据
    var strPkcs7Data = document.getElementById("txtSignData").value;
    if (strPkcs7Data == "") {
        addLog("请进行P7数据签名！");
        return;
    }
    //设置摘要算法
    var DigestMethod = document.getElementById("hashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);
    //Base64编码的待签名数据原文，当P7签名带原文时可以传入 ""
    var txtSignText = document.getElementById("txtSignText").value;
    if (txtSignText == "") {
        addLog("请输入需要签名的数据原文！");
        return;
    }
    var InData = _Base64encode(txtSignText);
    //是否带原文，1 不带原文 0 带原文
    var ulDetached = 0;
    rtn = token.SOF_VerifyDataToPKCS7(strPkcs7Data, InData, ulDetached);
    if (rtn != 0) {
        addLog("验签失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验签成功。");
}
//文件签名
function btnSignData_File() {
    var contentList = document.getElementById("contentList_Sign");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //设置摘要算法
    var DigestMethod = document.getElementById("hashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);
    //密钥类型
    var KeySpec = 1;//1代表签名类型
    //签名文件
    var InFile = document.getElementById("txtSignFile").value;
    if (InFile == "") {
        addLog("请输入需要签名的文件全路径！");
        return;
    }
    var signedData = token.SOF_SignFileToPKCS7(conName, KeySpec, InFile);
    if (signedData == null) {
        addLog("签名失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("签名成功。");
    document.getElementById("txtSignData").value = signedData;
}
//文件验签
function btnVerifySign_File() {
    //设置摘要算法
    var DigestMethod = document.getElementById("hashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);
    //签名后的数据
    var strPkcs7Data = document.getElementById("txtSignData").value;
    if (strPkcs7Data == "") {
        addLog("请进行P7文件签名！");
        return;
    }
    //签名文件的全路径
    var InFilePath = document.getElementById("txtSignFile").value;
    if (InFilePath == "") {
        addLog("请输入需要签名的文件全路径！");
        return;
    }
    rtn = token.SOF_VerifyFileToPKCS7(strPkcs7Data, InFilePath);
    if (rtn != 0) {
        addLog("验签失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验签成功。");
}
//数据签名---所见即所签交易(请确保UKey为K5-B4 或 按键型GM3000)
function btnTransPacketSign() {
    var contentList = document.getElementById("contentList_Sign");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //设置摘要算法
    var DigestMethod = document.getElementById("transPacketType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);
    //密钥类型
    var ulKeySpec = 1;
    //Base64编码的待签名数据原文
    var txtTransPacket = document.getElementById("txtTransPacket").value;
    if (txtTransPacket == "") {
        addLog("请输入交易报文(待签名的数据)！");
        return;
    }
    var InData = _Base64encode(txtTransPacket);
    var InDataLen = txtTransPacket.length;
    alert("提示： 请在60秒以内及时按下签名按钮……");
    var signedData = token.SOF_SignDataInteractive(conName, ulKeySpec, InData, InDataLen);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (signedData == null) {
        addLog("签名失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("签名成功。");
    document.getElementById("txtTransPacketSignData").value = signedData;
}
//数据验签---所见即所签交易(请确保UKey为K5-B4 或 按键型GM3000)
function btnTransPacketVerifySign() {
    //签名后的值
    var txtTransPacketSignData = document.getElementById("txtTransPacketSignData").value
    if (txtTransPacketSignData == "") {
        addLog("请进行签名！");
        return;
    }
    //获取Base64编码签名证书数据
    var Base64EncodeCert = document.getElementById("txtExportCerData").value;
    if (Base64EncodeCert == "") {
        addLog("请导出Ukey中的签名证书！");
        return;
    }
    //设置摘要算法
    var digestMethod = document.getElementById("transPacketType").value;
    //Base64编码的待签名数据原文
    var txtTransPacket = document.getElementById("txtTransPacket").value;
    if (txtTransPacket == "") {
        addLog("请输入交易报文(待签名的数据)！");
        return;
    }
    var InData = _Base64encode(txtTransPacket);
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID").value;
    token.SOF_SetUserID(userID);

    //0 预处理 1 不做预处理（当使用SM2签名时，必须用SM3摘要算法，则需要决定是否做预处理计算Z值）
    var mode = 0;
    rtn = token.SOF_VerifySignedData(Base64EncodeCert, Number(digestMethod), InData, txtTransPacketSignData, mode);
    if (rtn != 0) {
        addLog("验签失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("验签成功。");
}
//非对称加解密-获取容器列表
function btnGetConList_Asy() {
    if (!ensureAppSelected()) {
        return;
    }
    var conNameList = token.SOF_EnumCertContiner();
    if (conNameList == "") {
        addLog("未找到任何容器！");
        return;
    }
    if (conNameList == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var contentList = document.getElementById("contentList_Asy");
    contentList.options.length = 0;
    addOption(conNameList, contentList, 1);
    addLog("获取成功。");
}
//非对称加解密-导出容器下指定密钥对的公钥
function btnExportPubKey_Asy() {
    var contentList = document.getElementById("contentList_Asy");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //证书类型
    var pubKeyType = document.getElementById("pubKeyType_Asy").value;
    //选择导出公钥格式，1代表0016-2012国密标准格式
    var expType = 1;
    var pubData = token.SOF_ExportPubKey(conName, pubKeyType, expType);
    if (pubData == null) {
        addLog("导出失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("导出成功。");
    document.getElementById("txtExportPubKey_Asy").value = pubData;
}
//非对称加解密-公钥加密
function btnPubKeyEn_Asy() {
    //公钥
    var strPubKey = document.getElementById("txtExportPubKey_Asy").value;
    if (strPubKey == "") {
        addLog("请导出公钥数据！");
        return;
    }
    //待加密的数据
    var strInput = document.getElementById("txtText_Asy").value;
    if (strInput == "") {
        addLog("请输入需要加密的数据！");
        return;
    }
    var InData = _Base64encode(strInput);
    //密钥类型
    var cerType = document.getElementById("pubKeyType_Asy").value;
    var asymCipherData = token.SOF_EncryptByPubKey(strPubKey, InData, cerType);
    if (asymCipherData == null) {
        addLog("加密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("加密成功。");
    document.getElementById("txtData_Asy").value = asymCipherData;
}
//非对称加解密-私钥解密
function btnPriKeyDe_Asy() {
    var strAsymCipherData = document.getElementById("txtData_Asy").value;
    if (strAsymCipherData == "") {
        addLog("请进行加密！");
        return;
    }
    var contentList = document.getElementById("contentList_Asy");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //密钥类型
    var cerType = document.getElementById("pubKeyType_Asy").value;
    var asymPlainData = token.SOF_DecryptByPrvKey(conName, cerType, strAsymCipherData);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (asymPlainData == null) {
        addLog("解密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("解密成功。");
    document.getElementById("txtDataDe_Asy").value = _Base64decode(asymPlainData);
}
//数据对称加密
function btnAlgorithmEn() {
    //操作的设备名称
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //获取IV
    var iv = document.getElementById("txtIV").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //对称密钥
    var sessionKey = document.getElementById("txtSymmetricKey").value;
    if (sessionKey == "") {
        addLog("请输入对称密钥！");
        return;
    }
    var sessionKey_b64 = _Base64encode(sessionKey);
    //待加密的数据
    var inData = document.getElementById("txtDataEn_Sym").value;
    if (inData == "") {
        addLog("请输入待加密的数据！");
        return;
    }
    var inData_b64 = _Base64encode(inData);
    //设置对称算法IV
    rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
    if (rtn != 0) {
        addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var outData = token.SOF_SymEncryptData(deviceName, sessionKey_b64, inData_b64);
    if (outData == null) {
        addLog("加密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("加密成功。");
    document.getElementById("txtEnData_Sym").value = outData;
}
//数据对称解密
function btnAlgorithmDe() {
    //操作的设备名称
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //加密后的数据
    var inData_b64 = document.getElementById("txtEnData_Sym").value;
    if (inData_b64 == "") {
        addLog("加密后的数据为空，请加密！");
        return;
    }
    //获取IV
    var iv = document.getElementById("txtIV").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //对称密钥
    var sessionKey = document.getElementById("txtSymmetricKey").value;
    if (sessionKey == "") {
        addLog("请输入对称密钥！");
        return;
    }
    var sessionKey_b64 = _Base64encode(sessionKey);

    //设置对称算法IV
    rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
    if (rtn != 0) {
        addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var outData = token.SOF_SymDecryptData(deviceName, sessionKey_b64, inData_b64);
    if (outData == null) {
        addLog("解密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("解密成功。");
    document.getElementById("txtDeData_Sym").value = _Base64decode(outData);
}
//文件对称加密
function btnAlgorithmEnFile() {
    //操作的设备名称
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //获取IV
    var iv = document.getElementById("txtIV").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //对称密钥
    var sessionKey = document.getElementById("txtSymmetricKey").value;
    if (sessionKey == "") {
        addLog("请输入对称密钥！");
        return;
    }
    var sessionKey_b64 = _Base64encode(sessionKey);
    //待加密的文件
    var srcfile = document.getElementById("txtEnFile_Sym").value;
    if (srcfile == "") {
        addLog("请输入待加密文件的全路径！");
        return;
    }
    //加密后的文件
    var destfile = document.getElementById("txtEnFileAfter_Sym").value;
    if (destfile == "") {
        addLog("请输入加密后文件的全路径！");
        return;
    }
    //加密类型选择，1 硬件处理 0 软算法处理
    var type = document.getElementById("AlgorithmFileType").value;
    if (type == 0) {
        rtn = token.SOF_SymEncryptFile(deviceName, sessionKey_b64, srcfile, destfile, type, selAlgorithmTypeVal, iv_b64);
        if (rtn != 0) {
            addLog("加密失败，错误码：" + token.SOF_GetLastError());
            return;
        }
        addLog("加密成功。");
    } else {
        //设置对称算法IV
        rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
        if (rtn != 0) {
            addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
            return;
        }
        rtn = token.SOF_SymEncryptFile(deviceName, sessionKey_b64, srcfile, destfile, type);
        if (rtn != 0) {
            addLog("加密失败，错误码：" + token.SOF_GetLastError());
            return;
        }
        addLog("加密成功。");
    }

}
//文件对称解密
function btnAlgorithmDeFile() {
    //操作的设备名称
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }

    //获取IV
    var iv = document.getElementById("txtIV").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //对称密钥
    var sessionKey = document.getElementById("txtSymmetricKey").value;
    if (sessionKey == "") {
        addLog("请输入对称密钥！");
        return;
    }
    var sessionKey_b64 = _Base64encode(sessionKey);
    //加密后的文件
    var srcfile = document.getElementById("txtEnFileAfter_Sym").value;
    if (srcfile == "") {
        addLog("请输入加密后文件的全路径！");
        return;
    }
    //解密后的文件
    var destfile = document.getElementById("txtDeFileAfter_Sym").value;
    if (destfile == "") {
        addLog("请输入解密后文件的全路径！");
        return;
    }
    //加密类型选择，1 硬件处理 0 软算法处理
    var type = document.getElementById("AlgorithmFileType").value;
    if (type == 0) {
        rtn = token.SOF_SymDecryptFile(deviceName, sessionKey_b64, srcfile, destfile, type, selAlgorithmTypeVal, iv_b64);
        if (rtn != 0) {
            addLog("解密失败，错误码：" + token.SOF_GetLastError());
            return;
        }
        addLog("解密成功。");
    } else {
        //设置对称算法IV
        rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
        if (rtn != 0) {
            addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
            return;
        }
        rtn = token.SOF_SymDecryptFile(deviceName, sessionKey_b64, srcfile, destfile, type);
        if (rtn != 0) {
            addLog("解密失败，错误码：" + token.SOF_GetLastError());
            return;
        }
        addLog("解密成功。");
    }

}
//信封-获取容器列表
function btnGetConList_P7() {
    if (!ensureAppSelected()) {
        return;
    }
    var conNameList = token.SOF_EnumCertContiner();
    if (conNameList == "") {
        addLog("未找到任何容器！");
        return;
    }
    if (conNameList == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var contentList = document.getElementById("contentList_P7");
    contentList.options.length = 0;
    addOption(conNameList, contentList, 1);
    addLog("获取成功。");
}
//信封-导出加密证书
function btnExportCer_P7() {
    var contentList = document.getElementById("contentList_P7");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //获取导出证书的类型
    var cerType = document.getElementById("cerType_P7").value;
    var cert = token.SOF_ExportUserCert(conName, cerType);
    if (cert == null) {
        addLog("导出失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var txtExportCer = document.getElementById("txtExportCer_P7");
    txtExportCer.value = cert;
    addLog("导出成功。");
}
//信封-数据加密
function btnDataEn_P7() {
    var Base64EncodeCert = document.getElementById("txtExportCer_P7").value;
    if (Base64EncodeCert == "") {
        addLog("请导出加密证书！");
        return;
    }
    var InData = document.getElementById("txtDataEn_P7").value;
    if (InData == "") {
        addLog("请输入需要加密的数据！");
        return;
    }
    var InData_b64 = _Base64encode(InData);
    var InDataLen = InData.length;
    //获取IV
    var iv = document.getElementById("txtIV_P7").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType_P7");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //设置对称算法IV
    rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
    if (rtn != 0) {
        addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    //加密，对称密钥由设备随机生成；加密关系：使用证书公钥加密UKEY生成的随机对称密钥，使用对称密钥加密明文数据。
    var encrypedData = token.SOF_EncryptDataPKCS7EX(Base64EncodeCert, InData_b64, InDataLen);
    if (encrypedData == null) {
        addLog("加密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("加密成功。");
    document.getElementById("txtEnData_P7").value = encrypedData;
}
//信封-数据解密
function btnDataDe_P7() {
    //加密后的信封数据
    var InData = document.getElementById("txtEnData_P7").value;
    if (InData == "") {
        addLog("加密后的信封数据为空，请进行加密！");
        return;
    }
    var contentList = document.getElementById("contentList_P7");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //密钥类型
    var ulKeySpec = document.getElementById("cerType_P7").value;
    //获取IV
    var iv = document.getElementById("txtIV_P7").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType_P7");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //设置对称算法IV
    rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
    if (rtn != 0) {
        addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    //解密，对称密钥使用随机的同一个密钥；解密关系：使用容器中证书对应的私钥解密出对称密钥，使用对称密钥解密出明文数据。
    var decryptedData = token.SOF_DecryptDataPKCS7EX(conName, ulKeySpec, InData);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (decryptedData == null) {
        addLog("解密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("解密成功。");
    document.getElementById("txtDeData_P7").value = _Base64decode(decryptedData);
}
//信封-文件加密
function btnFileEn_P7() {
    var Cert = document.getElementById("txtExportCer_P7").value;
    if (Cert == "") {
        addLog("请导出加密证书！");
        return;
    }
    //待加密文件的全路径
    var InFile = document.getElementById("txtEnFile_P7").value;
    if (InFile == "") {
        addLog("请输入待加密文件的全路径！");
        return;
    }
    //加密后文件的全路径
    var OutFile = document.getElementById("txtEnFileAfter_P7").value;
    if (OutFile == "") {
        addLog("请输入加密后文件的全路径！");
        return;
    }
    //加密类型选择，1 硬件处理 0 软算法处理
    var type = 1;
    //获取IV
    var iv = document.getElementById("txtIV_P7").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType_P7");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //设置对称算法IV
    rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
    if (rtn != 0) {
        addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var envelopData = token.SOF_EncryptFileToPKCS7(Cert, InFile, OutFile, type);
    if (envelopData == null) {
        addLog("加密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("加密成功。");
    document.getElementById("txtEnDataAfter_P7").value = envelopData;
}
//信封-文件解密
function btnFileDe_P7() {
    //加密后的信封数据
    var Pkcs7Data = document.getElementById("txtEnDataAfter_P7").value;
    if (Pkcs7Data == "") {
        addLog("加密后的信封数据为空，请进行加密！");
        return;
    }
    var contentList = document.getElementById("contentList_P7");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //加密后文件的全路径
    var InFile = document.getElementById("txtEnFileAfter_P7").value;
    if (InFile == "") {
        addLog("请输入加密后文件的全路径！");
        return;
    }
    //解密后的文件全路径
    var OutFile = document.getElementById("txtDeFileAfter_P7").value;
    if (OutFile == "") {
        addLog("请输入解密后文件的全路径！");
        return;
    }
    //密钥类型
    var ulKeySpec = document.getElementById("cerType_P7").value;
    //获取IV
    var iv = document.getElementById("txtIV_P7").value;
    //获取对称算法
    var selAlgorithmType = document.getElementById("selAlgorithmType_P7");
    var index = selAlgorithmType.selectedIndex;
    // 获取选择的算法文本
    var selectedAlgorithm = selAlgorithmType.options[index].text;
    // 判断算法是否需要IV
    if (selectedAlgorithm.indexOf("CBC") !== -1 ||
        selectedAlgorithm.indexOf("CFB") !== -1 ||
        selectedAlgorithm.indexOf("OFB") !== -1) {
        // 判断IV文本框是否为空
        if (iv == "") {
            addLog("你选择的算法需要IV，请填写IV，IV不能为空！");
            return;
        }
    }
    var selAlgorithmTypeVal = selAlgorithmType.value;
    var iv_b64 = _Base64encode(iv);
    //设置对称算法IV
    rtn = token.SOF_SetEncryptMethodAndIV(selAlgorithmTypeVal, iv_b64);
    if (rtn != 0) {
        addLog("设置对称算法失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    //加密类型选择，1 硬件处理 0 软算法处理
    var type = 1;
    rtn = token.SOF_DecryptFileToPKCS7(conName, ulKeySpec, Pkcs7Data, InFile, OutFile, type);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请验证Ukey的用户密码！");
        return;
    }
    if (rtn != 0) {
        addLog("解密失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("解密成功。");
}
//SM3预处理-获取所有容器
function btnGetConList_Hash() {
    if (!ensureAppSelected()) {
        return;
    }
    var conNameList = token.SOF_EnumCertContiner();
    if (conNameList == "") {
        addLog("未找到任何容器！");
        return;
    }
    if (conNameList == null) {
        addLog("获取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    var contentList = document.getElementById("contentList_Hash");
    contentList.options.length = 0;
    addOption(conNameList, contentList, 1);
    addLog("获取成功。");
}
//SM3预处理计算摘要
function btnHashData() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    var contentList = document.getElementById("contentList_Hash");
    var indexConList = contentList.selectedIndex;
    if (indexConList < 0) {
        addLog("请获取需要操作的容器！");
        return;
    }
    //拿到容器名称
    var conName = contentList.options[indexConList].text;
    //设置摘要算法
    var DigestMethod = document.getElementById("selHashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    //设置userID，SM3算法，如果需要做预处理计算Z值，就需要设置userID
    var userID = document.getElementById("txtUserID_Hash").value;
    if (userID == "") {
        addLog("请输入用户ID ！");
        return;
    }
    token.SOF_SetUserID(userID);
    //待摘要的数据
    var InData = document.getElementById("txtHashText").value;
    if (InData == "") {
        addLog("请输入需要计算摘要的数据！");
        return;
    }
    var InData_b64 = _Base64encode(InData);
    var InDataLen = txtHashText.length;
    var digest = token.SOF_DigestData(deviceName, conName, InData_b64, InDataLen);
    if (digest == null) {
        addLog("摘要失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("摘要成功。");
    document.getElementById("txtHashData").value = digest;
}
//无预处理计算摘要，以及其他摘要算法
function btnHashData_notZ() {
    var deviceName = getSelectedDeviceName();
    if (deviceName == null) {
        return;
    }
    //待摘要的数据
    var InData = document.getElementById("txtHashText").value;
    if (InData == "") {
        addLog("请输入需要计算摘要的数据！");
        return;
    }
    //设置摘要算法
    var DigestMethod = document.getElementById("selHashType").value;
    token.SOF_SetDigestMethod(Number(DigestMethod));
    var InData_b64 = _Base64encode(InData);
    var InDataLen = txtHashText.length;
    var digest = token.SOF_DigestData(deviceName, "", InData_b64, InDataLen);
    if (digest == null) {
        addLog("摘要失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("摘要成功。");
    document.getElementById("txtHashData").value = digest;
}
//创建文件
function btnCreateFile() {
    if (!ensureAppSelected()) {
        return;
    }
    //文件名称
    var fileName = document.getElementById("txtFileName").value;
    if (fileName == "") {
        addLog("请输入需要创建的文件名称！");
        return;
    }
    //创建文件的大小-字节单位
    var fileSize = document.getElementById("txtFileSize").value;
    if (fileSize == "") {
        addLog("请输入创建文件的字节大小！")
        return;
    }
    //读文件权限
    var readRight = document.getElementById("selFileSecure").value;
    //写文件权限
    var writeRight = document.getElementById("selFileSecure").value;
    rtn = token.SOF_CreateFile(fileName, fileSize, readRight, writeRight);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请根据创建应用的权限，验证对应的密码！");
        return;
    }
    if (token.SOF_GetLastError() == "a00002f") {
        addLog("【" + fileName + "】文件已经存在！");
        return;
    }
    if (rtn != 0) {
        addLog("创建文件失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("创建【" + fileName + "】文件成功");
}
//枚举所有文件
function btnFindFile() {
    if (!ensureAppSelected()) {
        return;
    }
    var filelList = document.getElementById("filelList");
    filelList.options.length = 0;
    var array = token.SOF_EnumFiles();
    if (array == "") {
        addLog("没有找到任何文件！");
        return;
    }
    if (array == null) {
        addLog("枚举失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addOption(array, filelList, 1);
    addLog("枚举成功。");
}
//删除文件
function btnDelFile() {
    if (!ensureAppSelected()) {
        return;
    }
    var filelList = document.getElementById("filelList");
    var indexFileList = filelList.selectedIndex;
    if (indexFileList < 0) {
        addLog("请枚举需要操作的文件！");
        return;
    }
    //拿到文件名称
    var fileName = filelList.options[indexFileList].text;
    rtn = token.SOF_DeleteFile(fileName);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请根据创建应用的权限，验证对应的密码！");
        return;
    }
    if (rtn != 0) {
        addLog("删除文件失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("删除【" + fileName + "】文件成功");
}
//写入文件数据
function btnWriteData() {
    if (!ensureAppSelected()) {
        return;
    }
    var filelList = document.getElementById("filelList");
    var indexFileList = filelList.selectedIndex;
    if (indexFileList < 0) {
        addLog("请枚举需要操作的文件！");
        return;
    }
    //拿到文件名称
    var fileName = filelList.options[indexFileList].text;
    //写入的开始地址
    var offset = document.getElementById("txtWriteBeginAdd").value;
    if (offset == "") {
        addLog("请输入写入文件的开始地址！");
        return;
    }
    //需要写入的数据
    var inData = document.getElementById("txtWriteData").value;
    if (inData == "") {
        addLog("请输入需要写入的数据！");
        return;
    }
    var inData_b64 = _Base64encode(inData);
    rtn = token.SOF_WriteFile(fileName, offset, inData_b64);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请根据创建文件的权限，验证对应的密码！");
        return;
    }
    if (rtn != 0) {
        addLog("写入失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("写入成功。");
}
//读取文件
function btnReadData() {
    if (!ensureAppSelected()) {
        return;
    }
    var filelList = document.getElementById("filelList");
    var indexFileList = filelList.selectedIndex;
    if (indexFileList < 0) {
        addLog("请枚举需要操作的文件！");
        return;
    }
    //拿到文件名称
    var fileName = filelList.options[indexFileList].text;
    //读取的开始地址
    var offset = document.getElementById("txtReadBeginAdd").value;
    if (offset == "") {
        addLog("请输入读取文件的开始地址！");
        return;
    }
    //读取的长度
    var length = document.getElementById("txtReadLen").value;
    if (length == "") {
        addLog("请输入读取文件的长度！");
        return;
    }
    var outData = token.SOF_ReadFile(fileName, offset, length);
    if (token.SOF_GetLastError() == "a00002d") {
        addLog("请根据创建文件的权限，验证对应的密码！");
        return;
    }
    if (outData == null) {
        addLog("读取失败，错误码：" + token.SOF_GetLastError());
        return;
    }
    addLog("读取成功。");
    document.getElementById("txtReadData").value = _Base64decode(outData);
}