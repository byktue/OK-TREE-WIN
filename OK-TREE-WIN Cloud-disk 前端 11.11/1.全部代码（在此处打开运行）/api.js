// 简单的前端 API 客户端，封装 Authorization header、JSON 解析与文件下载
(function(global){
  const API_BASE = 'http://localhost:3000/api';
  const TOKEN_KEY = 'cloudDiskToken';
  const DEFAULT_CHUNK_SIZE = 2 * 1024 * 1024; // 2MB

  function getToken(){
    return localStorage.getItem(TOKEN_KEY) || '';
  }

  async function apiGet(path){
    const res = await fetch(API_BASE + path, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${getToken()}`,
        'Accept': 'application/json'
      }
    });
    const text = await res.text();
    try{ return JSON.parse(text); } catch(e){ return { success: res.ok, data: text }; }
  }

  async function apiPost(path, body, isForm=false){
    const headers = { 'Authorization': `Bearer ${getToken()}` };
    if (!isForm) headers['Content-Type'] = 'application/json';

    const res = await fetch(API_BASE + path, {
      method: 'POST',
      headers,
      body: isForm ? body : JSON.stringify(body)
    });
    const text = await res.text();
    try{ return JSON.parse(text); } catch(e){ return { success: res.ok, data: text }; }
  }

  // 下载接口，path 是以 / 开头的 API 路径（例如 /files/download?id=123）
  async function apiDownload(path, filename){
    const res = await fetch(API_BASE + path, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${getToken()}` }
    });
    if (!res.ok) throw new Error('下载失败: ' + res.status);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || '';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    return true;
  }

  async function getStorageUsage(){
    return apiGet('/storage/usage');
  }

  async function getFileBlob(path){
    const res = await fetch(API_BASE + path, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${getToken()}` }
    });
    if (!res.ok){
      throw new Error('获取文件内容失败: ' + res.status);
    }
    return res.blob();
  }

  // 上传单文件（FormData），返回解析后的JSON
  async function uploadFile(path, file, onProgress){
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const fd = new FormData();
      fd.append('file', file, file.name);

      xhr.open('POST', API_BASE + path, true);
      const token = getToken();
      if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token);

      xhr.upload.onprogress = function(e){
        if (e.lengthComputable && typeof onProgress === 'function'){
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      };

      xhr.onload = function(){
        if (xhr.status >=200 && xhr.status < 300){
          try{ resolve(JSON.parse(xhr.responseText)); } catch(e){ resolve({ success: true, data: xhr.responseText }); }
        } else {
          try{ reject(JSON.parse(xhr.responseText)); } catch(e){ reject(new Error('上传失败: ' + xhr.status)); }
        }
      };
      xhr.onerror = function(){ reject(new Error('上传网络错误')); };
      xhr.send(fd);
    });
  }

  async function startChunkUpload({ fileName, totalSize, chunkSize = DEFAULT_CHUNK_SIZE, parentId = null }) {
    const payload = { fileName, totalSize, chunkSize };
    if (parentId !== null && parentId !== undefined) {
      payload.parentId = parentId;
    }
    return apiPost('/upload/chunk/start', payload);
  }

  async function appendChunk(uploadId, chunkIndex, chunkBlob){
    const token = getToken();
    const url = `${API_BASE}/upload/chunk/append?uploadId=${encodeURIComponent(uploadId)}&chunkIndex=${chunkIndex}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: token ? { 'Authorization': `Bearer ${token}` } : {},
      body: chunkBlob
    });
    const text = await res.text();
    try { return JSON.parse(text); } catch(e) { return { success: res.ok, data: text }; }
  }

  async function completeChunkUpload(uploadId, parentId){
    const body = { uploadId };
    if (parentId !== null && parentId !== undefined) {
      body.parentId = parentId;
    }
    return apiPost('/upload/chunk/complete', body);
  }

  async function createShare(fileId, options = {}){
    const payload = { fileId };
    if (options.expireHours) payload.expireHours = options.expireHours;
    if (options.permissions) payload.permissions = options.permissions;
    return apiPost('/share/create', payload);
  }

  async function listShares(){
    return apiGet('/share/list');
  }

  async function joinCollab(fileId){
    return apiPost('/collab/join', { fileId });
  }

  async function pushCollab(sessionId, version, delta){
    return apiPost('/collab/push', { sessionId, version, delta });
  }

  async function pollCollab(sessionId, afterVersion){
    return apiGet(`/collab/poll?sessionId=${encodeURIComponent(sessionId)}&afterVersion=${afterVersion}`);
  }

  // 导出到全局
  global.CloudApi = {
    apiGet,
    apiPost,
    apiDownload,
    getFileBlob,
    uploadFile,
    getStorageUsage,
    startChunkUpload,
    appendChunk,
    completeChunkUpload,
    createShare,
    listShares,
    joinCollab,
    pushCollab,
    pollCollab
  };
})(window);
