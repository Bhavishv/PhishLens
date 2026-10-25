/**
 * Leaflet 1.9.4 Local Baseline & Resilient Stub
 * Provides core map, tileLayer, marker, polyline, and bounds API.
 * Can be upgraded to full Leaflet 1.9.4 distribution via download_vendor.py.
 */
(function (global) {
  if (global.L) return;

  function Map(containerId, options) {
    this.container = typeof containerId === "string" ? document.getElementById(containerId) : containerId;
    this.options = options || {};
    this.markers = [];
    this.polylines = [];
    if (this.container) {
      this.container.classList.add("leaflet-container");
    }
  }

  Map.prototype.setView = function (latlng, zoom) {
    this.center = latlng;
    this.zoom = zoom;
    return this;
  };

  Map.prototype.fitBounds = function () {
    return this;
  };

  Map.prototype.invalidateSize = function () {
    return this;
  };

  Map.prototype.remove = function () {
    if (this.container) {
      this.container.innerHTML = "";
    }
    return this;
  };

  function TileLayer(urlTemplate, options) {
    this.urlTemplate = urlTemplate;
    this.options = options || {};
  }
  TileLayer.prototype.addTo = function (map) {
    this.map = map;
    return this;
  };

  function Marker(latlng, options) {
    this.latlng = latlng;
    this.options = options || {};
  }
  Marker.prototype.addTo = function (map) {
    if (map && map.container) {
      const pin = document.createElement("div");
      pin.className = "leaflet-marker-icon";
      pin.style.cssText =
        "position:absolute;left:50%;top:50%;width:16px;height:16px;border-radius:50%;background:#ef4444;border:2px solid #ffffff;transform:translate(-50%,-50%);box-shadow:0 0 10px #ef4444;";
      map.container.appendChild(pin);
    }
    return this;
  };
  Marker.prototype.bindPopup = function (content) {
    this.popupContent = content;
    return this;
  };

  function Polyline(latlngs, options) {
    this.latlngs = latlngs;
    this.options = options || {};
  }
  Polyline.prototype.addTo = function () {
    return this;
  };

  global.L = {
    map: function (id, opts) {
      return new Map(id, opts);
    },
    tileLayer: function (url, opts) {
      return new TileLayer(url, opts);
    },
    marker: function (ll, opts) {
      return new Marker(ll, opts);
    },
    polyline: function (lls, opts) {
      return new Polyline(lls, opts);
    },
    latLngBounds: function () {
      return {
        isValid: function () {
          return true;
        },
      };
    },
  };
})(window);
