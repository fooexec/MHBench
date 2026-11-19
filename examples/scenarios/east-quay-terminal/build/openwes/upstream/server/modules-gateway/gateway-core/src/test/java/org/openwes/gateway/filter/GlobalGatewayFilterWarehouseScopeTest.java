package org.openwes.gateway.filter;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GlobalGatewayFilterWarehouseScopeTest {

    @Test
    void requiresWarehouseContextForStockFreezeAndUnfreeze() {
        assertTrue(GlobalGatewayFilter.requiresWarehouseScope(
                "/wms/stock/container/stock/freezeContainerStock",
                HttpMethod.POST
        ));
        assertTrue(GlobalGatewayFilter.requiresWarehouseScope(
                "/wms/stock/container/stock/unfreezeContainerStock",
                HttpMethod.POST
        ));
    }

    @Test
    void requiresWarehouseContextForOutboundPriorityChanges() {
        assertTrue(GlobalGatewayFilter.requiresWarehouseScope(
                "/wms/outbound/order/improvePriority",
                HttpMethod.POST
        ));
    }

    @Test
    void doesNotRequireWarehouseContextForReadsOrUnrelatedRoutes() {
        assertFalse(GlobalGatewayFilter.requiresWarehouseScope(
                "/wms/stock/container/stock/freezeContainerStock",
                HttpMethod.GET
        ));
        assertFalse(GlobalGatewayFilter.requiresWarehouseScope(
                "/user/api/currentUser",
                HttpMethod.POST
        ));
    }
}
