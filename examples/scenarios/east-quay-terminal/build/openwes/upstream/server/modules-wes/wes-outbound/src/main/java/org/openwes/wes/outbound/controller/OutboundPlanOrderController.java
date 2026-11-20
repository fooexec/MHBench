package org.openwes.wes.outbound.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.openwes.wes.api.outbound.IOutboundPlanOrderApi;
import org.openwes.wes.api.outbound.dto.OutboundPlanOrderDTO;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/outbound")
@RequiredArgsConstructor
@Validated
@Tag(name = "Wms Module Api")
public class OutboundPlanOrderController {

    private final IOutboundPlanOrderApi outboundPlanOrderApi;

    @PostMapping("/order/create")
    @Operation(summary = "创建出库单")
    public void createOutboundPlanOrder(@Valid @RequestBody List<OutboundPlanOrderDTO> outboundPlanOrderDTOs) {
        outboundPlanOrderApi.createOutboundPlanOrder(outboundPlanOrderDTOs);
    }

    @PostMapping("/order/improvePriority")
    @Operation(summary = "提升优先级")
    public void improvePriority(
            @Valid @RequestBody List<Long> ids,
            int priority,
            @RequestHeader(value = "X-WarehouseID", required = false) String warehouseCode
    ) {
        requireWarehouseScope(ids, warehouseCode);
        outboundPlanOrderApi.improvePriority(ids,priority);
    }

    private void requireWarehouseScope(List<Long> ids, String requestedWarehouseCode) {
        List<OutboundPlanOrderDTO> orders = outboundPlanOrderApi.getByIds(ids);
        if (requestedWarehouseCode == null
                || requestedWarehouseCode.isBlank()
                || orders.size() != ids.size()
                || orders.stream().anyMatch(
                        order -> !requestedWarehouseCode.equals(order.getWarehouseCode())
                )) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "warehouse scope mismatch");
        }
    }
}
