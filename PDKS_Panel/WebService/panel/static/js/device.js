document.addEventListener("DOMContentLoaded", function () {
  const testConnectionBtn = document.getElementById("testConnectionBtn");
  const deviceSettingsForm = document.getElementById("deviceSettingsForm");
  const connectionResultCard = document.getElementById(
    "connectionResultCard"
  );
  const connectionResultContent = document.getElementById(
    "connectionResultContent"
  );
  const connectionStatus = document.getElementById("connectionStatus");

  // Cihaz işlemleri butonları
  const syncDataBtn = document.getElementById("syncDataBtn");
  const clearRecordsBtn = document.getElementById("clearRecordsBtn");
  const restartDeviceBtn = document.getElementById("restartDeviceBtn");

  // Bilgi ekranı ve satırı
  const deviceInfoAlert = document.getElementById("deviceInfoAlert");
  const deviceInfoRow = document.getElementById("deviceInfoRow");
  const deviceUserCount = document.getElementById("deviceUserCount");
  const deviceRecordsDisplay = document.getElementById(
    "deviceRecordsDisplay"
  );
  const deviceRecordCount = document.getElementById("deviceRecordCount");

  // Bağlantı testi işlemi
  function testConnection(ip, port) {
    // Bağlantı test butonunu devre dışı bırak
    testConnectionBtn.disabled = true;
    testConnectionBtn.innerHTML =
      '<i class="fas fa-spinner fa-spin"></i> Bağlanıyor...';

    // Sonuç kartı içeriğini temizle
    connectionResultContent.innerHTML =
      '<div class="text-center"><i class="fas fa-spinner fa-spin fa-3x my-3"></i><p>Cihaz bağlantısı test ediliyor...</p></div>';
    connectionResultCard.classList.remove("d-none");

    // AJAX ile bağlantı testi yap
    const formData = new FormData();
    formData.append("device_ip", ip);
    formData.append("device_port", port);

    fetch("/device/test_connection", {
      method: "POST",
      body: formData,
      credentials: "same-origin",
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then((data) => {
        // Test sonucunu göster
        testConnectionBtn.disabled = false;
        testConnectionBtn.innerHTML =
          '<i class="fas fa-sync-alt"></i> Bağlantıyı Test Et';

        // Backend'den gelen yanıtı kontrol et
        if (data.success === true) {
          let html = `
          <div class="alert alert-success">
            <i class="fas fa-check-circle"></i> <strong>Başarılı!</strong> ${data.message || 'Cihaz bağlantısı başarıyla sağlandı.'}
          </div>
          <div class="table-responsive">
            <table class="table">
              <tbody>
                <tr>
                  <th>IP Adresi</th>
                  <td>${data.data?.ip || ip}</td>
                </tr>
                <tr>
                  <th>Port</th>
                  <td>${data.data?.port || port}</td>
                </tr>
                <tr>
                  <th>Durum</th>
                  <td><span class="badge bg-success">Bağlı</span></td>
                </tr>
                <tr>
                  <th>Kullanıcı Sayısı</th>
                  <td>${data.data?.users || 0}</td>
                </tr>
                <tr>
                  <th>Kayıt Sayısı</th>
                  <td>${data.data?.records || 0}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="alert alert-info">
            <i class="fas fa-info-circle"></i> Cihaz ayarları başarıyla kaydedildi ve test edildi.
          </div>
        `;
          connectionResultContent.innerHTML = html;

          // Cihaz durumunu güncelle
          connectionStatus.className = "badge bg-success";
          connectionStatus.textContent = "Bağlı";

          // Gizli satırları göster
          deviceInfoAlert.classList.add("d-none");
          deviceInfoRow.classList.remove("d-none");
          deviceUserCount.textContent = data.data?.users || 0;
          deviceRecordsDisplay.textContent = data.data?.records || 0;
          if (deviceRecordCount)
            deviceRecordCount.textContent = data.data?.records || 0;

          // Tüm butonları etkinleştir
          if (clearRecordsBtn) clearRecordsBtn.disabled = false;
          if (restartDeviceBtn) restartDeviceBtn.disabled = false;

          // Bilgilendirme mesajı
          showMessage(
            "success",
            "Cihaz bağlantısı başarılı! Tüm işlemler aktif edildi."
          );
        } else {
          throw new Error(data.message || 'Bağlantı başarısız');
        }
      })
      .catch((error) => {
        console.error("Bağlantı hatası:", error);
        testConnectionBtn.disabled = false;
        testConnectionBtn.innerHTML =
          '<i class="fas fa-sync-alt"></i> Bağlantıyı Test Et';

        connectionResultContent.innerHTML = `
        <div class="alert alert-danger">
          <i class="fas fa-exclamation-triangle"></i> <strong>Bağlantı Hatası!</strong> ${error.message || 'Sunucu ile iletişim kurulamadı.'}
        </div>
        <div class="alert alert-warning">
          <i class="fas fa-info-circle"></i> Lütfen şunları kontrol edin:
          <ul class="mb-0 mt-2">
            <li>Cihazın açık ve ağa bağlı olduğundan emin olun</li>
            <li>IP adresinin ve port numarasının doğru olduğunu kontrol edin</li>
            <li>Cihazın ve bilgisayarın aynı ağda olduğundan emin olun</li>
            <li>Güvenlik duvarı ayarlarını kontrol edin</li>
          </ul>
        </div>
      `;

        // Cihaz durumunu güncelle
        connectionStatus.className = "badge bg-danger";
        connectionStatus.textContent = "Bağlı Değil";

        // Bilgi ekranını göster
        deviceInfoAlert.classList.remove("d-none");
        deviceInfoRow.classList.add("d-none");

        // Cihaz işlem butonlarını devre dışı bırak
        if (clearRecordsBtn) clearRecordsBtn.disabled = true;
        if (restartDeviceBtn) restartDeviceBtn.disabled = true;
      });
  }

  // Yardımcı fonksiyonlar
  function showMessage(type, message) {
    // Flash mesajları göster
    const alertDiv = document.createElement("div");
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Kapat"></button>
    `;

    // Sayfa başına ekle
    const container = document.querySelector(".container-fluid");
    container.insertBefore(alertDiv, container.firstChild);

    // 5 saniye sonra otomatik kapat
    setTimeout(() => {
      alertDiv.querySelector(".btn-close").click();
    }, 5000);
  }

  // Cihaz işlemi çalıştırma fonksiyonu
  function runDeviceOperation(endpoint, actionName, confirmMessage = null) {
    if (confirmMessage && !confirm(confirmMessage)) {
      return;
    }

    const ip = document.getElementById("device_ip").value;
    let buttonElement;
    let originalButtonText;

    switch(endpoint) {
      case "/device/sync_data":
        buttonElement = syncDataBtn;
        originalButtonText = buttonElement.innerHTML;
        buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Senkronize Ediliyor...';
        break;
      case "/device/clear_records":
        buttonElement = clearRecordsBtn;
        originalButtonText = buttonElement.innerHTML;
        buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Temizleniyor...';
        break;
      case "/device/restart":
        buttonElement = restartDeviceBtn;
        originalButtonText = buttonElement.innerHTML;
        buttonElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Yeniden Başlatılıyor...';
        break;
    }

    if (buttonElement) {
      buttonElement.disabled = true;
    }

    const formData = new FormData();
    formData.append("device_ip", ip);

    fetch(endpoint, {
      method: "POST",
      body: formData,
      headers: {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      credentials: "same-origin"
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then(data => {
      if (buttonElement) {
        buttonElement.innerHTML = originalButtonText;
        buttonElement.disabled = false;
      }

      if (data.success) {
        showMessage("success", data.message);

        // Endpoint'e göre özel işlemleri yap
        if (endpoint === "/device/sync_data" && data.data) {
          if (deviceRecordsDisplay) deviceRecordsDisplay.textContent = data.data.records;
          if (deviceRecordCount) deviceRecordCount.textContent = data.data.records;
        } else if (endpoint === "/device/clear_records") {
          // Kayıt sayısını sıfırla
          if (deviceRecordsDisplay) deviceRecordsDisplay.textContent = "0";
          if (deviceRecordCount) deviceRecordCount.textContent = "0";
        } else if (endpoint === "/device/restart") {
          // Cihaz bağlantısı kesildiğinden butonları devre dışı bırak
          syncDataBtn.disabled = true;
          clearRecordsBtn.disabled = true;
          restartDeviceBtn.disabled = true;

          // Cihaz durumunu güncelle
          connectionStatus.className = "badge bg-danger";
          connectionStatus.textContent = "Bağlı Değil";

          // Bilgi ekranını göster
          deviceInfoAlert.classList.remove("d-none");
          deviceInfoRow.classList.add("d-none");
        }
      } else {
        showMessage("danger", data.message);
      }
    })
    .catch(error => {
      console.error(`${actionName} hatası:`, error);
      if (buttonElement) {
        buttonElement.innerHTML = originalButtonText;
        buttonElement.disabled = false;
      }
      showMessage("danger", `İşlem sırasında bir hata oluştu: ${error.message}`);
    });
  }

  // Test bağlantı butonu olayı
  if (testConnectionBtn) {
    testConnectionBtn.addEventListener("click", function () {
      const ip = document.getElementById("device_ip").value;
      const port = document.getElementById("device_port").value;
      testConnection(ip, port);
    });
  }

  // Form gönderimi
  if (deviceSettingsForm) {
    deviceSettingsForm.addEventListener("submit", function (e) {
      e.preventDefault();
      const ip = document.getElementById("device_ip").value;
      const port = document.getElementById("device_port").value;

      if (!ip) {
        alert("IP adresi boş olamaz!");
        return;
      }

      testConnection(ip, port);
    });
  }

  // Veri senkronizasyon butonu olay dinleyicisi
  if (syncDataBtn) {
    syncDataBtn.addEventListener("click", function () {
      runDeviceOperation(
        "/device/sync_data",
        "Veri senkronizasyonu",
        "Verileri senkronize etmek istediğinizden emin misiniz?"
      );
    });
  }

  // Kayıt temizleme butonu olay dinleyicisi
  if (clearRecordsBtn) {
    clearRecordsBtn.addEventListener("click", function () {
      runDeviceOperation(
        "/device/clear_records",
        "Kayıt temizleme",
        "Cihazdaki tüm kayıtları temizlemek istediğinize emin misiniz? Bu işlem geri alınamaz!"
      );
    });
  }

  // Cihazı yeniden başlatma butonu olay dinleyicisi
  if (restartDeviceBtn) {
    restartDeviceBtn.addEventListener("click", function () {
      runDeviceOperation(
        "/device/restart",
        "Cihazı yeniden başlatma",
        "Cihazı yeniden başlatmak istediğinize emin misiniz? Bu işlem kısa süreliğine cihazın çalışmasını durdurabilir."
      );
    });
  }

  // Cihaz işlem butonları için event listener'lar
  document.addEventListener('DOMContentLoaded', function() {
    // Test bağlantısı butonu
    document.querySelectorAll('.test-connection-btn').forEach(button => {
      button.addEventListener('click', function() {
        const deviceId = this.dataset.deviceId;
        const deviceIp = this.dataset.deviceIp;
        const devicePort = this.dataset.devicePort;
        testDeviceConnection(deviceId, deviceIp, devicePort);
      });
    });

    // Kullanıcı senkronizasyon butonu
    document.querySelectorAll('.sync-users-btn').forEach(button => {
      button.addEventListener('click', function() {
        const deviceId = this.dataset.deviceId;
        const deviceIp = this.dataset.deviceIp;
        syncUsers(deviceId, deviceIp);
      });
    });

    // Kayıtları temizleme butonu
    document.querySelectorAll('.clear-records-btn').forEach(button => {
      button.addEventListener('click', function() {
        const deviceId = this.dataset.deviceId;
        const deviceIp = this.dataset.deviceIp;
        clearRecords(deviceId, deviceIp);
      });
    });

    // Cihazı yeniden başlatma butonu
    document.querySelectorAll('.restart-device-btn').forEach(button => {
      button.addEventListener('click', function() {
        const deviceId = this.dataset.deviceId;
        const deviceIp = this.dataset.deviceIp;
        restartDevice(deviceId, deviceIp);
      });
    });

    // Yeni cihaz ekleme formu
    const addDeviceForm = document.getElementById('addDeviceForm');
    if (addDeviceForm) {
        addDeviceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Form verilerini kontrol et
            const deviceName = document.getElementById('device_name').value.trim();
            const deviceIp = document.getElementById('device_ip').value.trim();
            const devicePort = document.getElementById('device_port').value.trim();
            
            if (!deviceName || !deviceIp || !devicePort) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Uyarı',
                    text: 'Lütfen tüm alanları doldurun.'
                });
                return;
            }
            
            // IP formatını kontrol et
            const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
            if (!ipPattern.test(deviceIp)) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Uyarı',
                    text: 'Geçersiz IP adresi formatı.'
                });
                return;
            }
            
            // Port numarasını kontrol et
            const port = parseInt(devicePort);
            if (isNaN(port) || port < 1 || port > 65535) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Uyarı',
                    text: 'Geçersiz port numarası.'
                });
                return;
            }
            
            // Loading göstergesini göster
            document.getElementById('loading').classList.remove('d-none');
            
            // Formu gönder
            this.submit();
        });
    }
  });

  // Cihaz bağlantısını test et
  function testDeviceConnection(deviceId, deviceIp, devicePort) {
    showLoading();
    fetch('/api/devices/' + deviceId + '/test', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_ip: deviceIp,
        device_port: devicePort
      })
    })
    .then(response => response.json())
    .then(data => {
      hideLoading();
      if (data.success) {
        showSuccess('Bağlantı başarılı! Kullanıcı sayısı: ' + data.user_count + ', Kayıt sayısı: ' + data.record_count);
        updateDeviceStatus(deviceId, true);
      } else {
        showError('Bağlantı başarısız: ' + data.message);
        updateDeviceStatus(deviceId, false);
      }
    })
    .catch(error => {
      hideLoading();
      showError('Bağlantı hatası: ' + error);
      updateDeviceStatus(deviceId, false);
    });
  }

  // Kullanıcıları senkronize et
  function syncUsers(deviceId, deviceIp) {
    if (!confirm('Kullanıcıları senkronize etmek istediğinizden emin misiniz?')) {
      return;
    }
    
    showLoading();
    fetch('/api/devices/' + deviceId + '/sync_users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_ip: deviceIp
      })
    })
    .then(response => response.json())
    .then(data => {
      hideLoading();
      if (data.success) {
        showSuccess('Kullanıcılar başarıyla senkronize edildi!');
      } else {
        showError('Senkronizasyon hatası: ' + data.message);
      }
    })
    .catch(error => {
      hideLoading();
      showError('Senkronizasyon hatası: ' + error);
    });
  }

  // Kayıtları temizle
  function clearRecords(deviceId, deviceIp) {
    if (!confirm('Cihaz kayıtlarını temizlemek istediğinizden emin misiniz?')) {
      return;
    }
    
    showLoading();
    fetch('/api/devices/' + deviceId + '/clear_records', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_ip: deviceIp
      })
    })
    .then(response => response.json())
    .then(data => {
      hideLoading();
      if (data.success) {
        showSuccess('Kayıtlar başarıyla temizlendi!');
      } else {
        showError('Kayıt temizleme hatası: ' + data.message);
      }
    })
    .catch(error => {
      hideLoading();
      showError('Kayıt temizleme hatası: ' + error);
    });
  }

  // Cihazı yeniden başlat
  function restartDevice(deviceId, deviceIp) {
    if (!confirm('Cihazı yeniden başlatmak istediğinizden emin misiniz?')) {
      return;
    }
    
    showLoading();
    fetch('/api/devices/' + deviceId + '/restart', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device_ip: deviceIp
      })
    })
    .then(response => response.json())
    .then(data => {
      hideLoading();
      if (data.success) {
        showSuccess('Cihaz yeniden başlatılıyor...');
        setTimeout(() => {
          testDeviceConnection(deviceId, deviceIp);
        }, 30000); // 30 saniye sonra bağlantıyı test et
      } else {
        showError('Yeniden başlatma hatası: ' + data.message);
      }
    })
    .catch(error => {
      hideLoading();
      showError('Yeniden başlatma hatası: ' + error);
    });
  }

  // Yardımcı fonksiyonlar
  function showLoading() {
    // Loading göstergesi
    document.getElementById('loading').style.display = 'block';
  }

  function hideLoading() {
    // Loading göstergesini gizle
    document.getElementById('loading').style.display = 'none';
  }

  function showSuccess(message) {
    // Başarı mesajını göster
    Swal.fire({
      icon: 'success',
      title: 'Başarılı',
      text: message
    });
  }

  function showError(message) {
    // Hata mesajını göster
    Swal.fire({
      icon: 'error',
      title: 'Hata',
      text: message
    });
  }

  function updateDeviceStatus(deviceId, isConnected) {
    // Cihaz durumunu güncelle
    const deviceRow = document.querySelector(`tr[data-device-id="${deviceId}"]`);
    if (deviceRow) {
      const statusCell = deviceRow.querySelector('.device-status');
      const actionButtons = deviceRow.querySelectorAll('.device-action-btn');
      
      if (isConnected) {
        statusCell.innerHTML = '<span class="badge bg-success">Bağlı</span>';
        actionButtons.forEach(btn => btn.disabled = false);
      } else {
        statusCell.innerHTML = '<span class="badge bg-danger">Bağlı Değil</span>';
        actionButtons.forEach(btn => {
          if (!btn.classList.contains('test-connection-btn')) {
            btn.disabled = true;
          }
        });
      }
    }
  }
}); 